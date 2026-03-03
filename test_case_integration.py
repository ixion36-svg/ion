"""End-to-end integration test for case management: ION <-> Elasticsearch."""

import httpx
import json
import sys
import time

BASE = "http://127.0.0.1:8000"
ES_URL = "http://localhost:9200"
ES_AUTH = ("elastic", "DocforgeTest123!")

passed = 0
failed = 0


def report(name, ok, detail=""):
    global passed, failed
    if ok:
        passed += 1
        print(f"  [PASS] {name}")
    else:
        failed += 1
        print(f"  [FAIL] {name} -- {detail}")


def main():
    global passed, failed
    client = httpx.Client(base_url=BASE, timeout=15, follow_redirects=True)

    # ------------------------------------------------------------------
    # 1. Login
    # ------------------------------------------------------------------
    print("\n=== 1. Authentication ===")
    r = client.post("/api/auth/login", json={"username": "admin", "password": "Admin123!"})
    report("Login as admin", r.status_code == 200, f"status={r.status_code} body={r.text[:200]}")
    if r.status_code != 200:
        print("Cannot continue without auth. Exiting.")
        sys.exit(1)

    token = r.json().get("session_token") or r.json().get("token")
    # Also grab cookies set by the server
    cookies = dict(client.cookies)
    print(f"    Session token: {token[:16] if token else 'via cookie'}...")
    print(f"    Cookies: {list(cookies.keys())}")

    # ------------------------------------------------------------------
    # 2. Verify ES alerts are reachable via ION API
    # ------------------------------------------------------------------
    print("\n=== 2. Fetch Alerts via ION API ===")
    r = client.get("/api/elasticsearch/alerts", params={"hours": 48, "limit": 50})
    report("GET /api/elasticsearch/alerts", r.status_code == 200, f"status={r.status_code}")
    alerts_data = r.json()
    alerts = alerts_data.get("alerts", [])
    total = alerts_data.get("total", 0)
    report(f"Alerts returned ({total})", total > 0, f"total={total}")

    if not alerts:
        print("No alerts found. Cannot test case management. Exiting.")
        sys.exit(1)

    # Pick some alerts for our test case
    test_alerts = alerts[:3]
    alert_ids = [a["id"] for a in test_alerts]
    print(f"    Using {len(alert_ids)} alerts for case creation:")
    for a in test_alerts:
        print(f"      - [{a['severity'].upper()}] {a['title']} ({a['id'][:12]}...)")

    # ------------------------------------------------------------------
    # 3. Alert Stats
    # ------------------------------------------------------------------
    print("\n=== 3. Alert Statistics ===")
    r = client.get("/api/elasticsearch/alerts/stats", params={"hours": 48})
    report("GET /api/elasticsearch/alerts/stats", r.status_code == 200, f"status={r.status_code}")
    if r.status_code == 200:
        stats = r.json()
        print(f"    Total: {stats.get('total', 'N/A')}, By severity: {stats.get('by_severity', {})}")

    # ------------------------------------------------------------------
    # 4. Triage an alert (before case creation)
    # ------------------------------------------------------------------
    print("\n=== 4. Alert Triage ===")
    test_alert_id = alert_ids[0]
    r = client.put(f"/api/elasticsearch/alerts/{test_alert_id}/triage", json={
        "status": "investigating",
        "priority": "high",
        "analyst_notes": "Initial triage - reviewing alert context and related events.",
    })
    report("PUT triage (investigating)", r.status_code == 200, f"status={r.status_code} body={r.text[:200]}")

    r = client.get(f"/api/elasticsearch/alerts/{test_alert_id}/triage")
    report("GET triage", r.status_code == 200, f"status={r.status_code}")
    if r.status_code == 200:
        triage = r.json().get("triage", {})
        report("Triage status = investigating", triage.get("status") == "investigating",
               f"got: {triage.get('status')}")
        report("Triage priority = high", triage.get("priority") == "high",
               f"got: {triage.get('priority')}")

    # ------------------------------------------------------------------
    # 5. Add comment to alert
    # ------------------------------------------------------------------
    print("\n=== 5. Alert Comments ===")
    r = client.post(f"/api/elasticsearch/alerts/{test_alert_id}/comments", json={
        "content": "Confirmed malicious activity. Source IP 185.220.101.34 is a known Tor exit node. Escalating to case."
    })
    report("POST comment", r.status_code == 200, f"status={r.status_code} body={r.text[:200]}")

    # ------------------------------------------------------------------
    # 6. Auto-populate observables
    # ------------------------------------------------------------------
    print("\n=== 6. Auto-populate Observables ===")
    raw = test_alerts[0].get("raw_data", {})
    r = client.post(f"/api/elasticsearch/alerts/{test_alert_id}/triage/auto-populate-observables", json={
        "host": test_alerts[0].get("host"),
        "user": test_alerts[0].get("user"),
        "raw_data": raw,
    })
    report("POST auto-populate observables", r.status_code == 200, f"status={r.status_code} body={r.text[:200]}")
    if r.status_code == 200:
        obs = r.json().get("observables", [])
        report(f"Observables extracted ({len(obs)})", len(obs) > 0, f"count={len(obs)}")
        for o in obs[:5]:
            print(f"      {o['type']}: {o['value']}")

    # ------------------------------------------------------------------
    # 7. Create investigation case from alerts
    # ------------------------------------------------------------------
    print("\n=== 7. Create Investigation Case ===")
    hosts_for_case = list({a.get("host") for a in test_alerts if a.get("host")})
    users_for_case = list({a.get("user") for a in test_alerts if a.get("user")})
    rules_for_case = list({a.get("rule_name") for a in test_alerts if a.get("rule_name")})

    alert_contexts = []
    for a in test_alerts:
        alert_contexts.append({
            "alert_id": a["id"],
            "host": a.get("host"),
            "user": a.get("user"),
            "raw_data": a.get("raw_data", {}),
        })

    case_payload = {
        "title": "Suspected Intrusion - Brute Force + Lateral Movement Chain",
        "description": (
            "Multiple related alerts detected: brute force authentication from external IP, "
            "followed by suspicious PowerShell execution and possible lateral movement via PsExec. "
            "Initial compromise vector appears to be credential stuffing against RDP."
        ),
        "severity": "critical",
        "alert_ids": alert_ids,
        "affected_hosts": hosts_for_case,
        "affected_users": users_for_case,
        "triggered_rules": rules_for_case,
        "evidence_summary": (
            "1. Brute force: 237 failed logins from 185.220.101.34 in 5 min\n"
            "2. Successful RDP logon from same IP 3 min later\n"
            "3. Encoded PowerShell executed within 10 min of access\n"
            "4. PsExec service installed on adjacent server"
        ),
        "alert_contexts": alert_contexts,
    }

    r = client.post("/api/elasticsearch/alerts/cases", json=case_payload)
    report("POST create case", r.status_code == 200, f"status={r.status_code} body={r.text[:300]}")

    case_id = None
    case_number = None
    if r.status_code == 200:
        case_resp = r.json()
        case_id = case_resp.get("id")
        case_number = case_resp.get("case_number")
        linked = case_resp.get("linked_alerts", 0)
        report(f"Case created: {case_number}", case_id is not None, f"id={case_id}")
        report(f"Linked alerts ({linked})", linked == len(alert_ids), f"expected={len(alert_ids)}, got={linked}")
        print(f"    Case ID: {case_id}, Number: {case_number}")

    # ------------------------------------------------------------------
    # 7b. Verify case synced to Elasticsearch
    # ------------------------------------------------------------------
    print("\n=== 7b. Verify Case in Elasticsearch ===")
    if case_id:
        time.sleep(1)  # Allow ES to index
        es_client = httpx.Client(base_url=ES_URL, auth=ES_AUTH, timeout=10)
        r = es_client.get(f"/ion-cases/_doc/{case_id}")
        report("GET case from ES index", r.status_code == 200, f"status={r.status_code} body={r.text[:200]}")
        if r.status_code == 200:
            es_doc = r.json().get("_source", {})
            report("ES doc case_number matches", es_doc.get("case_number") == case_number,
                   f"expected={case_number}, got={es_doc.get('case_number')}")
            report("ES doc title matches", es_doc.get("title") == case_payload["title"],
                   f"got={es_doc.get('title', '')[:60]}")
            report("ES doc status = open", es_doc.get("status") == "open",
                   f"got={es_doc.get('status')}")
            report("ES doc severity = critical", es_doc.get("severity") == "critical",
                   f"got={es_doc.get('severity')}")
            report("ES doc has source_alert_ids", len(es_doc.get("source_alert_ids", [])) > 0,
                   f"count={len(es_doc.get('source_alert_ids', []))}")
            print(f"    ES doc keys: {list(es_doc.keys())}")
        es_client.close()

    # ------------------------------------------------------------------
    # 8. Add investigation notes to case
    # ------------------------------------------------------------------
    print("\n=== 8. Case Notes ===")
    if case_id:
        notes = [
            "Initial assessment: Attack chain consistent with TA0001 (Initial Access) -> TA0002 (Execution) -> TA0008 (Lateral Movement). Containment actions recommended.",
            "Isolated WKS-ANALYST01 from network pending forensic analysis. Captured memory dump.",
            "IOC sweep complete: found 3 additional hosts with Cobalt Strike beacon artifacts. Adding to case scope.",
        ]
        for note_text in notes:
            r = client.post(f"/api/elasticsearch/alerts/cases/{case_id}/notes", json={"content": note_text})
            report(f"POST note", r.status_code == 200, f"status={r.status_code}")

    # ------------------------------------------------------------------
    # 9. Update case status
    # ------------------------------------------------------------------
    print("\n=== 9. Update Case ===")
    if case_id:
        r = client.patch(f"/api/elasticsearch/alerts/cases/{case_id}", json={
            "status": "in_progress",
            "description": (
                "UPDATED: Scope expanded to include 3 additional compromised hosts. "
                "IR team actively investigating. Forensic images being acquired."
            ),
        })
        report("PATCH case -> in_progress", r.status_code == 200, f"status={r.status_code} body={r.text[:200]}")

    # ------------------------------------------------------------------
    # 9b. Verify ES reflects notes and status update
    # ------------------------------------------------------------------
    print("\n=== 9b. Verify ES After Notes & Update ===")
    if case_id:
        time.sleep(1)  # Allow ES to index
        es_client = httpx.Client(base_url=ES_URL, auth=ES_AUTH, timeout=10)
        r = es_client.get(f"/ion-cases/_doc/{case_id}")
        report("GET updated case from ES", r.status_code == 200, f"status={r.status_code}")
        if r.status_code == 200:
            es_doc = r.json().get("_source", {})
            report("ES doc status = in_progress", es_doc.get("status") == "in_progress",
                   f"got={es_doc.get('status')}")
            es_notes = es_doc.get("notes", [])
            report(f"ES doc notes count = 3", len(es_notes) == 3,
                   f"got={len(es_notes)}")
        es_client.close()

    # ------------------------------------------------------------------
    # 10. Get full case detail
    # ------------------------------------------------------------------
    print("\n=== 10. Case Detail ===")
    if case_id:
        r = client.get(f"/api/elasticsearch/alerts/cases/{case_id}")
        report("GET case detail", r.status_code == 200, f"status={r.status_code}")
        if r.status_code == 200:
            detail = r.json()
            report(f"Case number: {detail.get('case_number')}", detail.get("case_number") == case_number)
            report(f"Status = in_progress", detail.get("status") == "in_progress", f"got: {detail.get('status')}")
            report(f"Severity = critical", detail.get("severity") == "critical", f"got: {detail.get('severity')}")
            report(f"Linked alerts ({len(detail.get('alerts', []))})",
                   len(detail.get("alerts", [])) == len(alert_ids),
                   f"expected={len(alert_ids)}")
            report(f"Notes ({len(detail.get('notes', []))})", len(detail.get("notes", [])) == 3,
                   f"expected=3, got={len(detail.get('notes', []))}")
            report(f"Affected hosts present", bool(detail.get("affected_hosts")))
            report(f"Affected users present", bool(detail.get("affected_users")))
            report(f"Triggered rules present", bool(detail.get("triggered_rules")))
            report(f"Evidence summary present", bool(detail.get("evidence_summary")))

            print(f"\n    --- Case Summary ---")
            print(f"    {detail.get('case_number')}: {detail.get('title')}")
            print(f"    Status: {detail.get('status')} | Severity: {detail.get('severity')}")
            print(f"    Created by: {detail.get('created_by')}")
            print(f"    Hosts: {detail.get('affected_hosts')}")
            print(f"    Users: {detail.get('affected_users')}")
            print(f"    Rules: {detail.get('triggered_rules')}")
            print(f"    Linked alerts: {len(detail.get('alerts', []))}")
            print(f"    Notes: {len(detail.get('notes', []))}")

    # ------------------------------------------------------------------
    # 11. List all cases
    # ------------------------------------------------------------------
    print("\n=== 11. List Cases ===")
    r = client.get("/api/elasticsearch/alerts/cases")
    report("GET /api/elasticsearch/alerts/cases", r.status_code == 200, f"status={r.status_code}")
    if r.status_code == 200:
        cases = r.json().get("cases", [])
        report(f"Cases listed ({len(cases)})", len(cases) >= 1)

    # ------------------------------------------------------------------
    # 12. Batch triage fetch
    # ------------------------------------------------------------------
    print("\n=== 12. Batch Triage ===")
    r = client.post("/api/elasticsearch/alerts-triage/batch", json={"alert_ids": alert_ids})
    report("POST batch triage", r.status_code == 200, f"status={r.status_code}")
    if r.status_code == 200:
        triage_map = r.json().get("triage", {})
        report(f"Triage entries returned ({len(triage_map)})", len(triage_map) >= 1)
        for aid, t in triage_map.items():
            print(f"      {aid[:12]}... -> status={t.get('status')}, case={t.get('case_number')}")

    # ------------------------------------------------------------------
    # 13. Related alerts
    # ------------------------------------------------------------------
    print("\n=== 13. Related Alerts ===")
    host_for_related = test_alerts[0].get("host")
    if host_for_related:
        r = client.get(f"/api/elasticsearch/alerts/{test_alert_id}/related", params={
            "host": host_for_related,
            "hours": 48,
        })
        report("GET related alerts by host", r.status_code == 200, f"status={r.status_code}")
        if r.status_code == 200:
            related = r.json().get("related", {})
            by_host = related.get("by_host", [])
            print(f"    Related by host '{host_for_related}': {len(by_host)} alerts")

    # ------------------------------------------------------------------
    # Summary
    # ------------------------------------------------------------------
    print(f"\n{'='*50}")
    print(f"RESULTS: {passed} passed, {failed} failed, {passed + failed} total")
    print(f"{'='*50}")

    client.close()
    sys.exit(0 if failed == 0 else 1)


if __name__ == "__main__":
    main()
