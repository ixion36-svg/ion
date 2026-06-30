"""Drive the REAL RTMON pass against the REAL ION DB, with the mock Arkime
viewer (mock_arkime_rtmon.py) standing in for the Arkime session API.

This exercises the full production code path — expression sweep →
find_recent_sessions_by_expression → detectors → confirm-first gating →
_open_case (real AlertCase/Triage/Note rows) → PCAP enqueue — without needing a
real Arkime, real packet capture, or live traffic. Cleans up the cases it
creates afterward (unless --keep) so the dev DB is left as it was found.

Prereq: mock running on :8005.  Run:  python test-arkime/drive_rtmon.py
"""

import asyncio
import os
import sys
import time

# Point ION's ArkimeService at the mock + enable every content/behaviour detector.
os.environ["ION_ARKIME_URL"] = os.environ.get("MOCK_URL", "http://127.0.0.1:8005")
os.environ["ION_ARKIME_USERNAME"] = "arkime"
os.environ["ION_ARKIME_PASSWORD"] = "arkime"
os.environ["ION_ARKIME_VERIFY_SSL"] = "false"
os.environ["ION_ARKIME_RTMON_ENABLED"] = "true"
for d in ("CLEARTEXT", "COMMAND", "BEACON", "DNS"):
    os.environ[f"ION_ARKIME_RTMON_{d}_ENABLED"] = "true"
os.environ["ION_ARKIME_RTMON_IOC_ENABLED"] = "false"

from ion.models.alert_triage import AlertCase, AlertTriage, Note, NoteEntityType  # noqa: E402
from ion.services.arkime_realtime_monitor_service import _run_pass  # noqa: E402
from ion.services.arkime_service import get_arkime_service, reset_arkime_service  # noqa: E402
from ion.storage.database import get_engine, get_session_factory  # noqa: E402

KEEP = "--keep" in sys.argv


def _baseline(session) -> int:
    row = session.query(AlertCase.id).order_by(AlertCase.id.desc()).first()
    return row[0] if row else 0


async def main() -> int:
    reset_arkime_service()
    svc = get_arkime_service()
    print(f"Arkime configured: {svc.is_configured}  url={svc.url}")
    conn = await svc.test_connection()
    print(f"Arkime probe: {conn.get('connected')}  user={conn.get('user')}")
    if not conn.get("connected"):
        print("!! mock not reachable — start it: python test-arkime/mock_arkime_rtmon.py")
        return 2

    engine = get_engine()
    session = get_session_factory(engine)()
    baseline = _baseline(session)
    print(f"\nBaseline max AlertCase.id = {baseline}\n--- running _run_pass() ---")

    await _run_pass(engine)
    time.sleep(6)  # let background PCAP-enqueue threads annotate the cases

    session.expire_all()
    new_cases = session.query(AlertCase).filter(AlertCase.id > baseline).order_by(AlertCase.id).all()
    markers = {
        t.case_id: t.es_alert_id
        for t in session.query(AlertTriage).filter(AlertTriage.source_system == "arkime-rtmon").all()
    }
    print(f"\n=== RTMON opened {len(new_cases)} case(s) ===\n")
    for c in new_cases:
        print(f"  {c.case_number}  [{c.severity.upper()}]  {c.title}")
        print(f"      marker: {markers.get(c.id, '—')}")
        notes = session.query(Note).filter(
            Note.entity_type == NoteEntityType.CASE, Note.entity_id == str(c.id)
        ).all()
        for n in notes:
            first = (n.content or "").strip().splitlines()[0]
            print(f"      note:   {first}")
        print()

    detectors = sorted({m.split(":")[1] for m in markers.values() if m.count(":") >= 2})
    print(f"Detectors that fired: {detectors}")

    if not KEEP:
        ids = [c.id for c in new_cases]
        for c in new_cases:
            for n in session.query(Note).filter(
                Note.entity_type == NoteEntityType.CASE, Note.entity_id == str(c.id)
            ).all():
                session.delete(n)
        session.query(AlertTriage).filter(AlertTriage.case_id.in_(ids)).delete(synchronize_session=False)
        session.query(AlertCase).filter(AlertCase.id.in_(ids)).delete(synchronize_session=False)
        session.commit()
        print(f"\nCleaned up {len(ids)} test case(s) (and their triage/notes). Dev DB restored.")
    else:
        print("\n--keep set: leaving cases in the DB.")
    session.close()
    return 0


if __name__ == "__main__":
    raise SystemExit(asyncio.run(main()))
