"""Local bob_eval harness: seed labelled ground truth, then run the quantitative
evaluation against whatever model ION is configured to use.

The shipped bob_eval scores Bob's fresh verdict against the human verdict stored
in the ai_feedback ledger — ground truth that only exists once real cases have
been closed. A fresh / dev DB has none, so this seeds a small, balanced,
clearly-labelled set (true_positive / false_positive / benign_true_positive /
inconclusive) as Investigation + AIFeedback rows the harness can replay.

Usage:
  ION_OLLAMA_MODEL=... python tools/bob_eval_local.py seed
  ION_OLLAMA_MODEL=... python tools/bob_eval_local.py run [sample_size]

NOT a shipped artefact — a local evaluation utility. Seeded rows use the
alert_id prefix 'SEED-EVAL-' and are wiped + re-created on each `seed`.
"""
from __future__ import annotations

import sys

from ion.models.ai_feedback import AIFeedback
from ion.models.alert_prompt import AlertPromptTemplate
from ion.models.investigation import Investigation
from ion.storage.database import get_session

_PREFIX = "SEED-EVAL-"

# (rule, human_verdict ground truth, <input_data> alert body for replay)
_SCENARIOS = [
    ("Suspicious Encoded PowerShell Execution", "true_positive",
     "rule: Suspicious Encoded PowerShell Execution\nhost: WS-FIN-07 (Windows 10)\n"
     "user: jbloggs\nparent_process: WINWORD.EXE\nprocess: powershell.exe\n"
     "command_line: powershell.exe -nop -w hidden -enc SQBFAFgAKABOAGUAdwApAC4ALi4u\n"
     "destination.ip: 185.220.101.34 (known Tor exit node)\nevent.action: process_creation\n"
     "mitre: T1059.001, T1566"),
    ("Credential Dumping via LSASS Access", "true_positive",
     "rule: Credential Dumping - LSASS Memory Access\nhost: DC-01 (domain controller)\n"
     "user: svc_backup\nprocess: rundll32.exe\ncommand_line: rundll32.exe comsvcs.dll, MiniDump 624 lsass.dmp full\n"
     "target_process: lsass.exe\nevent.action: process_access\nmitre: T1003.001"),
    ("DNS Query to Known C2 Domain", "true_positive",
     "rule: DNS Query to Known-Bad Domain\nhost: WS-HR-12\nuser: asmith\n"
     "dns.question.name: kx7f2-update.duckdns.org (TI: Cobalt Strike C2, high confidence)\n"
     "network: 47 queries in 6 minutes at fixed 8s interval (beaconing)\nmitre: T1071.004, T1571"),
    ("Mass File Rename to Ransom Extension", "true_positive",
     "rule: Possible Ransomware - Mass File Modification\nhost: FS-03 (file server)\n"
     "user: jdoe\nprocess: unknown.exe\nobservation: 4,210 files renamed to *.locked in 90s; "
     "ransom note _RECOVER_FILES.txt written to every directory\nmitre: T1486"),
    ("Authorized Vulnerability Scan", "benign_true_positive",
     "rule: Network Recon - Port Scan Detected\nhost: scanned range 10.20.0.0/24\n"
     "source.ip: 10.20.99.5 (Nessus scanner, in approved scanning subnet, change CHG0041 active)\n"
     "observation: sequential TCP connects across 1-1024\nmitre: T1046"),
    ("EICAR Antivirus Test File", "benign_true_positive",
     "rule: Malware Detected - AV Signature Hit\nhost: WS-IT-02\nuser: itadmin\n"
     "file.name: eicar.com\nfile.path: C:\\Users\\itadmin\\Downloads\\eicar.com\n"
     "signature: EICAR-Test-File (not a virus — standard AV test artefact)\nmitre: T1204"),
    ("Approved Admin PsExec During Change Window", "benign_true_positive",
     "rule: Lateral Movement - PsExec Service Creation\nhost: APP-07\nuser: admin_patch (sanctioned admin)\n"
     "process: PSEXESVC.exe\ncontext: change ticket CHG0052 patch deployment window active; "
     "source host is the admin jump box ADM-JUMP-01\nmitre: T1569.002"),
    ("Single User Password Typo Then Success", "false_positive",
     "rule: Possible Brute Force - Repeated Auth Failures\nhost: VPN-GW\nuser: mwilson\n"
     "observation: 3 failed logons then 1 success, all from the user's normal corporate IP "
     "10.2.7.40 within 40 seconds; no other accounts targeted\nmitre: T1110"),
    ("Internal Backup Copy Flagged as Exfil", "false_positive",
     "rule: Possible Data Exfiltration - Large Outbound Transfer\nhost: DBSRV-02\n"
     "user: svc_backup\nprocess: robocopy.exe\ndestination.ip: 10.10.5.20 (internal backup NAS, RFC1918)\n"
     "observation: nightly scheduled backup job, matches baseline volume\nmitre: T1048"),
    ("Sparse Alert - Insufficient Context", "inconclusive",
     "rule: Anomalous Activity Detected\nhost: (not populated)\nobservation: rule fired with no "
     "process, network, user, or file fields; only @timestamp and rule.name present"),
]


def _wrap(body: str) -> str:
    return "<input_data>\n# ALERT TO INVESTIGATE\n\n" + body + "\n</input_data>"


def seed() -> None:
    for db in get_session():
        tmpl = db.query(AlertPromptTemplate).order_by(AlertPromptTemplate.id).first()
        if tmpl is None:
            print("ERROR: no AlertPromptTemplate rows — cannot render a contract-bearing system prompt.")
            return
        tid = tmpl.id

        # Wipe prior seed rows (idempotent).
        old = db.query(AIFeedback).filter(AIFeedback.alert_id.like(_PREFIX + "%")).all()
        old_inv = {f.investigation_id for f in old if f.investigation_id}
        for f in old:
            db.delete(f)
        for iid in old_inv:
            inv = db.get(Investigation, iid)
            if inv is not None:
                db.delete(inv)
        db.flush()

        n = 0
        for i, (rule, human_verdict, body) in enumerate(_SCENARIOS, 1):
            alert_id = f"{_PREFIX}{i:03d}"
            inv = Investigation(
                alert_id_ref=alert_id,
                alert_signature=rule,
                status="completed",
                verdict=human_verdict,           # prior (ignored by the metric)
                prompt_snapshot=_wrap(body),     # the body the harness replays
                prompt_template_id=tid,
                llm_model_used="seed",
            )
            db.add(inv)
            db.flush()
            db.add(AIFeedback(
                investigation_id=inv.id,
                alert_id=alert_id,
                alert_prompt_template_id=tid,
                bob_suggested_verdict=human_verdict,
                human_verdict=human_verdict,     # GROUND TRUTH
                agreement=True,
                bob_confidence_int=80,
                auto_escalated=False,
                human_closed_by_id=1,
            ))
            n += 1
        db.commit()
        print(f"Seeded {n} labelled samples under template_id={tid} ('{tmpl.name}').")


def run(sample_size: int) -> None:
    import asyncio

    from ion.core.circuit_breaker import CircuitState, ollama_breaker
    from ion.services.bob_eval_service import _run_eval_sync, create_eval_run
    from ion.services.ollama_service import get_ollama_service

    svc = get_ollama_service()
    print(f"Model under test: {svc.default_model} (num_ctx={svc.num_ctx}, timeout={svc.timeout}s)")

    # Warm the model into RAM so the first scored sample doesn't cold-start into
    # the timeout (CPU cold load is what tripped the breaker on the first run).
    print("Warming model (cold load can take 1-2 min on CPU)...")
    try:
        asyncio.run(svc.chat(
            messages=[{"role": "user", "content": "Reply with the single word: ready"}],
            system_prompt="You are a test harness probe. Reply with one word.",
            temperature=0.0, max_tokens=8, bypass_queue=True, user_id=0,
        ))
        print("  warm-up ok")
    except Exception as e:  # noqa: BLE001
        print(f"  warm-up failed: {e}")

    # Reset the breaker so a cold-start hiccup doesn't carry into the run.
    ollama_breaker._state = CircuitState.CLOSED
    ollama_breaker._failure_count = 0
    ollama_breaker._last_failure_time = None

    for db in get_session():
        run_row = create_eval_run(
            template_id=None, sample_size=sample_size, triggered_by_id=1, session=db
        )
        run_id = run_row.id
    print(f"Started eval run #{run_id} (sample_size={sample_size}). Per-sample model calls -- slow on CPU...")
    _run_eval_sync(run_id)

    from ion.models.bob_eval import BobEvalRun, BobEvalRunSample
    for db in get_session():
        r = db.get(BobEvalRun, run_id)
        print("\n=== RESULT ===")
        print(f"model={r.model_name} status={r.status}")
        print(f"TP={r.tp_count} FP={r.fp_count} FN={r.fn_count} "
              f"abstentions={r.abstention_count} skipped={r.skipped_count}")
        print(f"precision={r.precision_score} recall={r.recall_score} f1={r.f1_score} "
              f"hallucination_proxy={r.hallucination_proxy}")
        samples = db.query(BobEvalRunSample).filter(BobEvalRunSample.eval_run_id == run_id).all()
        print("\nper-sample (human_verdict <- bob_verdict, agree):")
        for s in samples:
            print(f"  human={s.human_verdict:>20}  bob={str(s.bob_verdict):>20}  agree={s.agreement}")


if __name__ == "__main__":
    cmd = sys.argv[1] if len(sys.argv) > 1 else "run"
    if cmd == "seed":
        seed()
    elif cmd == "run":
        size = int(sys.argv[2]) if len(sys.argv) > 2 else 10
        run(size)
    else:
        print(__doc__)
