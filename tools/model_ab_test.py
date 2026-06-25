"""Ad-hoc A/B of candidate Bob LLMs across ION's three real LLM surfaces.

NOT a shipped artefact — a local evaluation harness for choosing Bob's model.
For each model it exercises, via ION's own OllamaService (so request mechanics
match production):

  1. Investigation verdict — the `format:"json"` envelope path. The make-or-break
     test: does the model emit a VALID, schema-correct JSON verdict? (Reasoning
     models tend to wrap JSON in chain-of-thought and fail this.)
  2. Case-wide analysis — free-text, using bob_analysis_api's real system prompt.
  3. Closure rewrite — free-text, length-capped (mirrors ai_api.closure_rewrite).

Run:  python tools/model_ab_test.py "model1" "model2" ...
"""
from __future__ import annotations

import asyncio
import json
import sys
import time

from ion.services.ollama_service import get_ollama_service

# Real free-text system prompt ION sends for case analysis.
from ion.web.bob_analysis_api import _SYSTEM_PROMPT as CASE_ANALYSIS_SYSTEM

# ── Representative inputs ────────────────────────────────────────────────

_VERDICT_SYSTEM = (
    "You are Bob, ION's autonomous SOC analyst. Analyse the alert and respond "
    "with ONLY a single JSON object — no prose, no markdown — with EXACTLY "
    "these keys: "
    '{"verdict": one of "true_positive"|"false_positive"|"benign_true_positive"'
    '|"inconclusive", "confidence": integer 0-100, "severity_assessment": one '
    'of "low"|"medium"|"high"|"critical", "key_observations": array of short '
    'strings, "suggested_closure_reason": one of "true_positive"|'
    '"false_positive"|"benign_true_positive"|"duplicate"|"insufficient_data"|'
    '"not_applicable"}.'
)

_ALERT = (
    "## Alert\n"
    "- rule_name: Suspicious Encoded PowerShell Execution\n"
    "- rule_description: Detects base64-encoded PowerShell command lines commonly "
    "used by loaders and droppers to stage second-stage payloads.\n"
    "- host: WS-FIN-07 (Windows 10, finance VLAN)\n"
    "- user_name: jbloggs\n"
    "- parent_process_name: WINWORD.EXE\n"
    "- process_name: powershell.exe\n"
    "- process_command_line: powershell.exe -nop -w hidden -enc "
    "SQBFAFgAKABOAGUAdwAtAE8AYgBqAGUAYwB0AC4ALi4u\n"
    "- source_ip: 10.2.4.7\n"
    "- destination_ip: 185.220.101.34 (known Tor exit node)\n"
    "- event_action: process_creation\n"
    "- mitre: T1059.001 (PowerShell), T1566 (Phishing)\n"
)

_CASE_USER = (
    "## Case under review\n- Case: CASE-2026-0420 — 'Office-spawned PowerShell to Tor'\n"
    "- Severity: high\n\n"
    "## Well-known fields across all alerts\n"
    "### Alert 1 — Suspicious Encoded PowerShell\n" + _ALERT + "\n"
    "### Alert 2 — Outbound to Tor exit\n"
    "- rule_name: Outbound Connection to Tor Exit Node\n"
    "- host: WS-FIN-07\n- destination_ip: 185.220.101.34\n"
    "- network_bytes: 248113\n- event_action: network_flow\n\n"
    "## Observables\n- ipv4 = 185.220.101.34 (source: investigation)\n"
    "- host = WS-FIN-07\n\nProduce the verdict + evidence + next-steps sections."
)

_CLOSURE_DRAFT = (
    "looked at it, winword spawned powershell with encoded command, beaconed to "
    "a tor exit, isolated the host and reset jbloggs creds. real thing. closing tp"
)
_CLOSURE_SYSTEM = (
    "You are assisting a SOC analyst writing the closing comment for a security "
    "investigation case. Closure reason: true positive. Rewrite the draft below "
    "into a clear, concise, professional rationale; preserve every fact; do not "
    "invent details. Keep it SHORT: two to three brief paragraphs, four at most "
    "(~150 words). Respond with ONLY the rewritten comment as plain text.\n\n"
    f'Draft:\n"""\n{_CLOSURE_DRAFT}\n"""'
)

_VERDICT_ENUM = {"true_positive", "false_positive", "benign_true_positive", "inconclusive"}
_REQUIRED_KEYS = {"verdict", "confidence", "severity_assessment", "key_observations",
                  "suggested_closure_reason"}


async def _one_model(svc, model: str) -> dict:
    out: dict = {"model": model}

    # 1. JSON verdict path
    t = time.time()
    try:
        r = await svc.chat(
            messages=[{"role": "user", "content": _ALERT}],
            system_prompt=_VERDICT_SYSTEM, model=model,
            response_format="json", temperature=0.2, bypass_queue=True,
        )
        raw = (r.get("content") or "").strip()
        verdict = {}
        try:
            verdict = json.loads(raw)
            valid = isinstance(verdict, dict)
        except Exception:
            valid = False
        out["verdict"] = {
            "latency_s": round(time.time() - t, 1),
            "json_valid": valid,
            "has_all_keys": valid and _REQUIRED_KEYS.issubset(verdict.keys()),
            "verdict_in_enum": valid and verdict.get("verdict") in _VERDICT_ENUM,
            "verdict_value": verdict.get("verdict") if valid else None,
            "raw_excerpt": raw[:240],
        }
    except Exception as e:
        out["verdict"] = {"error": f"{type(e).__name__}: {e}"}

    # 2. Free-text case analysis
    t = time.time()
    try:
        r = await svc.chat(
            messages=[{"role": "user", "content": _CASE_USER}],
            system_prompt=CASE_ANALYSIS_SYSTEM, model=model,
            temperature=0.4, bypass_queue=True,
        )
        txt = (r.get("content") or "").strip()
        out["case_analysis"] = {
            "latency_s": round(time.time() - t, 1),
            "words": len(txt.split()),
            "mentions_verdict": any(k in txt.lower() for k in ("true_positive", "true positive")),
            "excerpt": txt[:500],
        }
    except Exception as e:
        out["case_analysis"] = {"error": f"{type(e).__name__}: {e}"}

    # 3. Closure rewrite
    t = time.time()
    try:
        r = await svc.chat(
            messages=[{"role": "user", "content": "Rewrite per the instructions."}],
            system_prompt=_CLOSURE_SYSTEM, model=model,
            temperature=0.3, max_tokens=400, bypass_queue=True,
        )
        txt = (r.get("content") or "").strip()
        out["closure_rewrite"] = {
            "latency_s": round(time.time() - t, 1),
            "words": len(txt.split()),
            "text": txt[:700],
        }
    except Exception as e:
        out["closure_rewrite"] = {"error": f"{type(e).__name__}: {e}"}

    return out


async def main(models: list[str]) -> None:
    svc = get_ollama_service()
    results = []
    for m in models:
        print(f"\n=== {m} ===", flush=True)
        res = await _one_model(svc, m)
        results.append(res)
        v = res.get("verdict", {})
        print(f"  [verdict]  json_valid={v.get('json_valid')} all_keys={v.get('has_all_keys')} "
              f"enum_ok={v.get('verdict_in_enum')} value={v.get('verdict_value')} "
              f"{v.get('latency_s')}s {v.get('error','')}")
        print(f"             raw: {v.get('raw_excerpt','')!r}")
        c = res.get("case_analysis", {})
        print(f"  [analysis] {c.get('words')}w {c.get('latency_s')}s mentions_verdict={c.get('mentions_verdict')} {c.get('error','')}")
        print(f"             {c.get('excerpt','')!r}")
        cr = res.get("closure_rewrite", {})
        print(f"  [rewrite]  {cr.get('words')}w {cr.get('latency_s')}s {cr.get('error','')}")
        print(f"             {cr.get('text','')!r}")
    print("\n=== JSON ===")
    print(json.dumps(results, indent=2))


if __name__ == "__main__":
    asyncio.run(main(sys.argv[1:]))
