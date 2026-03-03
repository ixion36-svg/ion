"""Seed SOC-CMM data: maturity assessments, certifications, knowledge articles.

Usage:
    python seed_soc_cmm.py

Requires ION to be running at http://127.0.0.1:8000
Admin: admin / admin2025
"""

import os
import sys
from datetime import date, timedelta
from pathlib import Path

# Add src to path for direct DB access
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "src"))

from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from ion.models.base import Base
from ion.models.skills import (
    KnowledgeArticle, SOCCMMAssessment, SkillAssessment, TeamCertification,
)
from ion.models.user import User


def main():
    db_path = Path(os.path.dirname(os.path.abspath(__file__))) / ".ion" / "ion.db"
    if not db_path.exists():
        db_path = Path.home() / ".ion" / "ion.db"
    print(f"Using database: {db_path}")
    engine = create_engine(f"sqlite:///{db_path}", echo=False)
    Base.metadata.create_all(engine)
    factory = sessionmaker(bind=engine, expire_on_commit=False)
    db = factory()

    # ── SOC-CMM People Domain Maturity Assessment ───────────────────
    print("\n--- SOC-CMM People Domain Maturity ---")
    CMM_DATA = [
        {
            "aspect": "employees",
            "rating": 3, "target_rating": 4,
            "notes": "8 staff, mix of L1-L3 plus specialists. Need 2 more for 24/7 coverage.",
        },
        {
            "aspect": "roles",
            "rating": 2, "target_rating": 4,
            "notes": "Role definitions exist but career progression paths need formalisation.",
        },
        {
            "aspect": "people_mgmt",
            "rating": 2, "target_rating": 3,
            "notes": "Annual reviews done. Need structured 1-on-1s and performance metrics.",
        },
        {
            "aspect": "knowledge_mgmt",
            "rating": 1, "target_rating": 3,
            "notes": "Mostly tribal knowledge. Runbooks exist for top 5 alert types only.",
        },
        {
            "aspect": "training",
            "rating": 2, "target_rating": 4,
            "notes": "Ad-hoc training. Need structured programme aligned to skill gaps.",
        },
    ]

    admin = db.query(User).filter(User.username == "admin").first()
    admin_id = admin.id if admin else 1

    for item in CMM_DATA:
        existing = db.query(SOCCMMAssessment).filter(
            SOCCMMAssessment.aspect == item["aspect"]
        ).first()
        if existing:
            existing.rating = item["rating"]
            existing.target_rating = item["target_rating"]
            existing.notes = item["notes"]
            existing.assessed_by_id = admin_id
            existing.assessed_date = date.today()
            print(f"  Updated: {item['aspect']} = {item['rating']}/{item['target_rating']}")
        else:
            db.add(SOCCMMAssessment(
                aspect=item["aspect"],
                rating=item["rating"],
                target_rating=item["target_rating"],
                notes=item["notes"],
                assessed_by_id=admin_id,
                assessed_date=date.today(),
            ))
            print(f"  Created: {item['aspect']} = {item['rating']}/{item['target_rating']}")
    db.commit()

    # ── Team Certifications ─────────────────────────────────────────
    print("\n--- Team Certifications ---")

    # Get user IDs
    users = {}
    for u in db.query(User).filter(User.is_active == True).all():
        users[u.username] = u.id

    CERTS = [
        # Sarah - L2 analyst aspiring to threat hunter
        {"user": "soc_sarah", "cert": "CompTIA Security+", "body": "CompTIA", "obtained": -400, "expiry": 695, "status": "active"},
        {"user": "soc_sarah", "cert": "CySA+", "body": "CompTIA", "obtained": -120, "expiry": 975, "status": "active"},
        # Marcus - L3 analyst aspiring to SOC lead
        {"user": "soc_marcus", "cert": "CompTIA Security+", "body": "CompTIA", "obtained": -900, "expiry": 195, "status": "active"},
        {"user": "soc_marcus", "cert": "GCIA", "body": "GIAC", "obtained": -200, "expiry": 895, "status": "active"},
        {"user": "soc_marcus", "cert": "GCIH", "body": "GIAC", "obtained": -500, "expiry": 595, "status": "active"},
        # Priya - Threat intel specialist
        {"user": "soc_priya", "cert": "CTIA", "body": "EC-Council", "obtained": -300, "expiry": 795, "status": "active"},
        {"user": "soc_priya", "cert": "GOSI", "body": "GIAC", "obtained": None, "expiry": None, "status": "planned"},
        # James - Incident responder
        {"user": "soc_james", "cert": "GCFE", "body": "GIAC", "obtained": -150, "expiry": 945, "status": "active"},
        {"user": "soc_james", "cert": "GNFA", "body": "GIAC", "obtained": -60, "expiry": 1035, "status": "active"},
        {"user": "soc_james", "cert": "EnCE", "body": "OpenText", "obtained": -400, "expiry": -35, "status": "expired"},
        # Elena - Detection engineer
        {"user": "soc_elena", "cert": "Splunk Core Certified Power User", "body": "Splunk", "obtained": -200, "expiry": 895, "status": "active"},
        {"user": "soc_elena", "cert": "Elastic Certified Engineer", "body": "Elastic", "obtained": -90, "expiry": 1005, "status": "active"},
        # Tom - L1 (new, minimal certs)
        {"user": "soc_tom", "cert": "CompTIA Security+", "body": "CompTIA", "obtained": -30, "expiry": 1065, "status": "active"},
        # Aisha - Security engineer
        {"user": "soc_aisha", "cert": "AWS Security Specialty", "body": "AWS", "obtained": -250, "expiry": 845, "status": "active"},
        {"user": "soc_aisha", "cert": "CKS", "body": "CNCF", "obtained": -100, "expiry": 995, "status": "active"},
        {"user": "soc_aisha", "cert": "CISSP", "body": "ISC2", "obtained": None, "expiry": None, "status": "planned"},
        # Chen Wei - Threat hunter
        {"user": "soc_chen", "cert": "OSCP", "body": "OffSec", "obtained": -180, "expiry": None, "status": "active"},
        {"user": "soc_chen", "cert": "GREM", "body": "GIAC", "obtained": None, "expiry": None, "status": "planned"},
        {"user": "soc_chen", "cert": "GCTI", "body": "GIAC", "obtained": -350, "expiry": 745, "status": "active"},
    ]

    today = date.today()
    count = 0
    for c in CERTS:
        uid = users.get(c["user"])
        if not uid:
            print(f"  User {c['user']} not found, skipping")
            continue
        # Check if cert already exists for this user
        existing = db.query(TeamCertification).filter(
            TeamCertification.user_id == uid,
            TeamCertification.cert_name == c["cert"],
        ).first()
        if existing:
            print(f"  Already exists: {c['user']} - {c['cert']}")
            continue
        obtained = today + timedelta(days=c["obtained"]) if c["obtained"] else None
        expiry = today + timedelta(days=c["expiry"]) if c["expiry"] else None
        db.add(TeamCertification(
            user_id=uid,
            cert_name=c["cert"],
            issuing_body=c["body"],
            obtained_date=obtained,
            expiry_date=expiry,
            status=c["status"],
        ))
        count += 1
        print(f"  Added: {c['user']} - {c['cert']} ({c['status']})")
    db.commit()
    print(f"  Total: {count} certifications added")

    # ── Knowledge Articles ──────────────────────────────────────────
    print("\n--- Knowledge Management ---")

    # Map capability keys from SOC_CAPABILITIES in training.html
    KNOWLEDGE = [
        {
            "key": "Incident Response",
            "doc_status": "basic", "has_runbooks": True, "has_procedures": True,
            "knowledge_sharing": "shared", "spof_risk": False,
            "notes": "Top 5 alert types have runbooks. IR plan reviewed quarterly.",
        },
        {
            "key": "Threat Intelligence",
            "doc_status": "basic", "has_runbooks": False, "has_procedures": True,
            "knowledge_sharing": "siloed", "spof_risk": True,
            "notes": "Priya is sole TI specialist. Intel workflows undocumented.",
        },
        {
            "key": "Detection Engineering",
            "doc_status": "comprehensive", "has_runbooks": True, "has_procedures": True,
            "knowledge_sharing": "shared", "spof_risk": False,
            "notes": "Detection-as-code pipeline documented. CI/CD in place.",
        },
        {
            "key": "Digital Forensics",
            "doc_status": "basic", "has_runbooks": True, "has_procedures": False,
            "knowledge_sharing": "siloed", "spof_risk": True,
            "notes": "James is primary forensics resource. Evidence handling SOP exists.",
        },
        {
            "key": "SIEM & Log Analysis",
            "doc_status": "comprehensive", "has_runbooks": True, "has_procedures": True,
            "knowledge_sharing": "trained", "spof_risk": False,
            "notes": "Log onboarding guide complete. Parser library maintained.",
        },
        {
            "key": "Network Defense",
            "doc_status": "basic", "has_runbooks": False, "has_procedures": False,
            "knowledge_sharing": "siloed", "spof_risk": True,
            "notes": "Firewall rules tribal knowledge. Need topology documentation.",
        },
        {
            "key": "Scripting & Automation",
            "doc_status": "basic", "has_runbooks": False, "has_procedures": True,
            "knowledge_sharing": "shared", "spof_risk": False,
            "notes": "Code review process exists. Need standardised library.",
        },
        {
            "key": "Offensive Security",
            "doc_status": "undocumented", "has_runbooks": False, "has_procedures": False,
            "knowledge_sharing": "siloed", "spof_risk": True,
            "notes": "Chen does ad-hoc purple team exercises. No formal programme.",
        },
        {
            "key": "Governance & Leadership",
            "doc_status": "basic", "has_runbooks": False, "has_procedures": True,
            "knowledge_sharing": "shared", "spof_risk": False,
            "notes": "SOC charter exists. KPIs defined but not consistently tracked.",
        },
        {
            "key": "Security Architecture",
            "doc_status": "undocumented", "has_runbooks": False, "has_procedures": False,
            "knowledge_sharing": "siloed", "spof_risk": True,
            "notes": "Aisha handles arch reviews. No formal security architecture docs.",
        },
    ]

    # Assign owners based on top skill holder
    owner_map = {
        "Incident Response": users.get("soc_james"),
        "Threat Intelligence": users.get("soc_priya"),
        "Detection Engineering": users.get("soc_elena"),
        "Digital Forensics": users.get("soc_james"),
        "SIEM & Log Analysis": users.get("soc_marcus"),
        "Network Defense": users.get("soc_aisha"),
        "Scripting & Automation": users.get("soc_aisha"),
        "Offensive Security": users.get("soc_chen"),
        "Governance & Leadership": users.get("soc_marcus"),
        "Security Architecture": users.get("soc_aisha"),
    }

    ka_count = 0
    for k in KNOWLEDGE:
        existing = db.query(KnowledgeArticle).filter(
            KnowledgeArticle.capability_key == k["key"]
        ).first()
        if existing:
            existing.doc_status = k["doc_status"]
            existing.has_runbooks = k["has_runbooks"]
            existing.has_procedures = k["has_procedures"]
            existing.knowledge_sharing = k["knowledge_sharing"]
            existing.spof_risk = k["spof_risk"]
            existing.owner_user_id = owner_map.get(k["key"])
            existing.notes = k["notes"]
            print(f"  Updated: {k['key']} ({k['doc_status']})")
        else:
            db.add(KnowledgeArticle(
                capability_key=k["key"],
                doc_status=k["doc_status"],
                has_runbooks=k["has_runbooks"],
                has_procedures=k["has_procedures"],
                knowledge_sharing=k["knowledge_sharing"],
                spof_risk=k["spof_risk"],
                owner_user_id=owner_map.get(k["key"]),
                notes=k["notes"],
            ))
            print(f"  Created: {k['key']} ({k['doc_status']})")
        ka_count += 1
    db.commit()
    print(f"  Total: {ka_count} knowledge articles")

    db.close()
    print("\n=== SOC-CMM seed complete ===")


if __name__ == "__main__":
    main()
