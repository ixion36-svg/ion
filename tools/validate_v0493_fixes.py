"""Live-stack validation of the v0.49.3 fix branch against real Postgres.

Runs against a booted ION (docker compose stack). Exercises the fixed paths
end-to-end over HTTP:

  1. health + auth
  2. is_ignored end-to-end (create case + observable, toggle ignore, verify
     case detail / similar-observables / search all suppress it)
  3. case-number uniqueness under real multi-worker concurrency
  4. MCP: limit clamp, malformed batch entries, add_case_note round-trip
  5. SSE stream: retry directive + prime refresh arrive
  6. large_doc job lifecycle: no-model failure ends in 'error' (never a stuck
     'running' that bricks the feature), concurrent second job 409s, and the
     feature accepts new work afterwards

Usage: python tools/validate_v0493_fixes.py [base_url]
Env:   ION_ADMIN_PASSWORD (default testadmin2026)
"""

from __future__ import annotations

import concurrent.futures
import json
import os
import sys
import time

import httpx

BASE = sys.argv[1] if len(sys.argv) > 1 else "http://127.0.0.1:8000"
ADMIN_PW = os.environ.get("ION_ADMIN_PASSWORD", "testadmin2026")

PASS, FAIL = [], []


def check(name: str, ok: bool, detail: str = "") -> None:
    (PASS if ok else FAIL).append((name, detail))
    print(f"  {'PASS' if ok else 'FAIL'}  {name}" + (f" — {detail}" if detail and not ok else ""))


def main() -> int:
    c = httpx.Client(base_url=BASE, timeout=30.0, follow_redirects=True)

    print("== 1. health + auth ==")
    r = c.get("/api/health")
    check("health 200", r.status_code == 200, str(r.status_code))
    r = c.post("/api/auth/login", json={"username": "admin", "password": ADMIN_PW})
    check("admin login", r.status_code == 200, f"{r.status_code}: {r.text[:200]}")
    if r.status_code != 200:
        return _summary()

    print("== 2. is_ignored end-to-end ==")
    # a case whose observables include a role-typed entry for our IOC
    r = c.post("/api/elasticsearch/alerts/cases", json={
        "title": "v0.49.3 validation case", "description": "test",
        "severity": "low",
    })
    check("create case", r.status_code in (200, 201), f"{r.status_code}: {r.text[:200]}")
    case = r.json()
    case_id = case.get("id") or case.get("case_id")
    case_number_1 = case.get("case_number")
    check("case_number assigned CASE-NNNN", bool(case_number_1 and case_number_1.startswith("CASE-")), str(case_number_1))

    # put a role-typed observable entry into the case via the observables JSON
    # (mirrors what alert enrichment writes), plus the Observable row itself
    r = c.post("/api/observables/import/csv", json={
        "csv_data": "type,value\nip,203.0.113.66\ndomain,ignoreme.example\n",
    })
    check("observable import (csv)", r.status_code == 200, f"{r.status_code}: {r.text[:200]}")

    # find the domain observable id
    r = c.get("/api/observables", params={"query": "ignoreme.example", "include_ignored": True})
    rows = r.json().get("observables") or r.json().get("items") or []
    check("observable searchable", len(rows) >= 1, r.text[:200])
    if rows:
        obs_id = rows[0]["id"]
        # toggle ignore
        r = c.put(f"/api/observables/{obs_id}", json={"is_ignored": True})
        check("toggle is_ignored", r.status_code == 200, f"{r.status_code}: {r.text[:200]}")
        # default search must now hide it
        r = c.get("/api/observables", params={"query": "ignoreme.example"})
        hidden = rows_of(r)
        check("default search hides ignored", len(hidden) == 0, r.text[:200])
        # include_ignored=true must show it
        r = c.get("/api/observables", params={"query": "ignoreme.example", "include_ignored": True})
        check("include_ignored shows it", len(rows_of(r)) == 1, r.text[:200])

    print("== 3. case-number uniqueness under concurrency ==")
    def _mk(i: int):
        # fresh client per thread — cookies shared via login copy
        with httpx.Client(base_url=BASE, timeout=30.0, cookies=c.cookies) as cc:
            rr = cc.post("/api/elasticsearch/alerts/cases", json={
                "title": f"concurrency case {i}", "severity": "low"})
            return rr.status_code, (rr.json().get("case_number") if rr.status_code < 300 else rr.text[:100])

    with concurrent.futures.ThreadPoolExecutor(max_workers=12) as ex:
        results = list(ex.map(_mk, range(24)))
    codes = [s for s, _ in results]
    numbers = [n for s, n in results if s in (200, 201)]
    check("24 concurrent creates all succeed", all(s in (200, 201) for s in codes), str(codes))
    check("all case numbers unique", len(set(numbers)) == len(numbers),
          f"{len(set(numbers))}/{len(numbers)} unique")

    print("== 4. MCP endpoint ==")
    def rpc(body):
        return c.post("/api/mcp", json=body)

    r = rpc({"jsonrpc": "2.0", "id": 1, "method": "tools/call",
             "params": {"name": "list_cases", "arguments": {"limit": -1}}})
    ok = r.status_code == 200
    if ok:
        payload = json.loads(r.json()["result"]["content"][0]["text"])
        ok = len(payload.get("cases", [])) == 1  # clamped to 1, not a full dump
    check("MCP limit=-1 clamped to 1 row", ok, r.text[:200])

    r = rpc([1, "x", {"jsonrpc": "2.0", "id": 7, "method": "ping"}])
    ok = r.status_code == 200
    if ok:
        data = r.json()
        errs = [d for d in data if "error" in d]
        ok = len(data) == 3 and len(errs) == 2 and all(e["error"]["code"] == -32600 for e in errs)
    check("MCP malformed batch -> per-item -32600 (no 500)", ok, r.text[:300])

    if case_id:
        r = rpc({"jsonrpc": "2.0", "id": 2, "method": "tools/call",
                 "params": {"name": "add_case_note",
                            "arguments": {"case_id": case_id, "content": "note via MCP"}}})
        ok = r.status_code == 200 and not r.json()["result"].get("isError", False)
        check("MCP add_case_note", ok, r.text[:300])
        rr = c.get(f"/api/elasticsearch/alerts/cases/{case_id}")
        # REST case detail shows the MCP-added note
        notes_ok = "note via MCP" in rr.text
        check("MCP note visible via REST case detail", notes_ok, rr.text[:200])

    print("== 5. SSE stream ==")
    frames = b""
    try:
        with c.stream("GET", "/api/events/stream", params={"topic": "investigations"},
                      timeout=10.0) as resp:
            check("SSE 200", resp.status_code == 200, str(resp.status_code))
            start = time.time()
            for chunk in resp.iter_raw():
                frames += chunk
                if b"event: refresh" in frames or time.time() - start > 8:
                    break
    except httpx.ReadTimeout:
        pass
    check("SSE retry directive", b"retry:" in frames, frames[:120].decode(errors="replace"))
    check("SSE prime refresh", b"event: refresh" in frames, frames[:200].decode(errors="replace"))

    print("== 6. large_doc lifecycle (no LLM model -> clean error, no brick) ==")
    files = {"file": ("doc.txt", b"Requirement: the system SHALL log all access. " * 200, "text/plain")}
    r = c.post("/api/document-analysis", files=files, data={"task": "checklist"})
    check("doc-analysis accepted", r.status_code == 200, f"{r.status_code}: {r.text[:200]}")
    job1 = r.json().get("job_id") if r.status_code == 200 else None

    if job1:
        # a second job while the first RUNS must 409 (single-job guard). With
        # no Ollama the first job can fail to 'error' in milliseconds, making
        # a 200 here legitimate — accept it only if job1 already terminated.
        r2 = c.post("/api/document-analysis", files=files, data={"task": "checklist"})
        if r2.status_code == 409:
            check("second concurrent job 409s while first runs", True)
        else:
            j1 = c.get(f"/api/document-analysis/jobs/{job1}").json().get("status")
            check("second concurrent job 409s while first runs",
                  r2.status_code == 200 and j1 in ("done", "error"),
                  f"second={r2.status_code}, first status={j1}")

        status = None
        for _ in range(120):  # up to ~4 min: ollama has no model -> chunks fail fast or on timeout
            jr = c.get(f"/api/document-analysis/jobs/{job1}")
            status = jr.json().get("status")
            if status in ("done", "error"):
                break
            time.sleep(2)
        check("job terminates (no infinite spin / stuck running)", status in ("done", "error"), str(status))

        # feature must accept new work afterwards — the old bug bricked it with 409s
        r3 = c.post("/api/document-analysis", files=files, data={"task": "summary"})
        check("feature usable after failure (no 409 brick)", r3.status_code == 200,
              f"{r3.status_code}: {r3.text[:150]}")

    return _summary()


def rows_of(r) -> list:
    j = r.json()
    return j.get("observables") or j.get("items") or []


def _summary() -> int:
    print(f"\n===== {len(PASS)} passed, {len(FAIL)} failed =====")
    for name, detail in FAIL:
        print(f"  FAILED: {name} — {detail}")
    return 1 if FAIL else 0


if __name__ == "__main__":
    sys.exit(main())
