"""Spike: is a server round trip per filter click acceptable for ION's queue?

The question came out of the UI design work: the HTMX direction replaces
client-side row building with a server-rendered fragment, so every filter
click costs a round trip. Does that feel instant?

What this measures, and why only this:

The current alerts page ALREADY pays a server round trip. alerts.html:3642
fetches /api/elasticsearch/alerts, and alerts.html:7340 then builds the
rows in JS from the JSON. So HTMX does not add a round trip. It reuses the
same one and swaps what comes back: HTML instead of JSON, with no client
build. The only NEW server cost is Jinja rendering the rows.

So this measures that marginal cost, plus the payload difference, and
leaves the query time out of it deliberately: that cost is identical in
both designs and would only flatter or muddy the comparison.

The partial under test is _queue_rows.html, written to match the work
alerts.html:7340 does rather than a simplified version: 12 columns, the
same per-field escaping, both conditional badges, the case badge, the
status fallback and the four quick actions with the conditional Arkime
SVG.

Run:  python tools/bench_htmx_rows.py
"""
from __future__ import annotations

import json
import statistics
import sys
import time
from pathlib import Path

from jinja2 import Environment, FileSystemBytecodeCache, FileSystemLoader, select_autoescape

ROOT = Path(__file__).resolve().parent.parent
# The fixture lives beside this tool, not in the app's template tree.
# It is a benchmark input, never rendered by a route, and leaving it
# under templates/ made it an orphan in the redesign inventory and
# inflated the "82 live templates" count by one.
TEMPLATES = ROOT / "tools" / "fixtures"
CACHE = Path("/tmp/ion-jinja2-bench-cache")

SIZES = [25, 50, 100, 250, 500, 1000, 2000]
ITERS = 200
WARMUP = 20

# The perceived-instant threshold. Nielsen's 100 ms is the figure usually
# cited for "the system reacted immediately"; past it a user notices the
# wait even if they do not mind it.
INSTANT_MS = 100.0


def make_env() -> Environment:
    """A Jinja env configured the way ion.web.templating.make_templates does.

    Same bytecode cache and same autoescape, because both change the number
    materially: the cache removes compile time from the steady state, and
    autoescape is what makes this comparable to escapeHtml() in the JS path.
    Importing make_templates itself would drag in config and licensing, which
    the row render does not touch.
    """
    CACHE.mkdir(parents=True, exist_ok=True)
    return Environment(
        loader=FileSystemLoader(str(TEMPLATES)),
        autoescape=select_autoescape(["html"]),
        bytecode_cache=FileSystemBytecodeCache(str(CACHE)),
        auto_reload=False,
    )


def make_alerts(n: int) -> list[dict]:
    """n rows shaped like the JSON the current page already receives.

    Field lengths are taken from the seeded demo alerts so string escaping
    and output size are representative, not minimal.
    """
    rules = [
        "Impossible travel: m.okafor UK to BR in 40 min",
        "LSASS handle opened by unsigned binary",
        "Defender tamper: real-time protection disabled",
        "Suspicious PowerShell -enc on FIN-WS-214",
        "Kerberoasting: 14 SPN requests from HR-WS-07",
        "Outbound beacon to 185.199.108.153:8443, 60s jitter",
        "Mailbox rule forwarding to external domain",
    ]
    hosts = ["FIN-WS-214", "LDN-VPN-02", "HR-WS-07", "OPS-SRV-11", "mail-gw-01", "DC-01"]
    sevs = ["critical", "high", "medium", "low"]
    out = []
    for i in range(n):
        out.append({
            "id": f"a1b2c3d4-e5f6-4a7b-8c9d-{i:012d}",
            "triage_status": ("none", "acknowledged", "in_progress")[i % 3],
            "severity": sevs[i % 4],
            "title": rules[i % 7],
            "host": hosts[i % 6],
            "user": f"user{i % 40}@example.local",
            "rule_name": rules[i % 7],
            "system": ("elasticsearch", "edr", "postgres")[i % 3],
            "case_number": f"CASE-2026-{i:04d}" if i % 4 == 0 else None,
            "case_title": "Suspected credential theft on finance workstation" if i % 4 == 0 else None,
            "effective_status": ("open", "acknowledged", "in_progress")[i % 3],
            "timestamp_display": "2026-10-11 02:38:14",
            "mitre_technique_id": f"T{1000 + (i % 600)}" if i % 2 == 0 else None,
            "mitre_technique_name": "OS Credential Dumping: LSASS Memory" if i % 2 == 0 else None,
            "mitre_tactic_name": "Credential Access" if i % 2 == 0 else None,
            "is_lab_fixture": i % 11 == 0,
            "has_network": i % 3 == 0,
            "network_community_id": "1:aBcDeFgHiJkLmNoPqRsTuVwXyZ0=" if i % 6 == 0 else None,
        })
    return out


def timed(fn, iters: int, warmup: int) -> list[float]:
    for _ in range(warmup):
        fn()
    samples = []
    for _ in range(iters):
        t0 = time.perf_counter()
        fn()
        samples.append((time.perf_counter() - t0) * 1000.0)
    return samples


def pct(xs: list[float], p: float) -> float:
    s = sorted(xs)
    k = max(0, min(len(s) - 1, int(round((p / 100.0) * (len(s) - 1)))))
    return s[k]


def main() -> int:
    env = make_env()
    try:
        tpl = env.get_template("_queue_rows.html")
    except Exception as exc:  # noqa: BLE001
        print(f"could not load _queue_rows.html from {TEMPLATES}: {exc}")
        return 1

    print(f"jinja render of _queue_rows.html, {ITERS} iterations after {WARMUP} warmup")
    print(f"bytecode cache: {CACHE}  autoescape: on  auto_reload: off")
    print()
    print(f"{'rows':>6} {'p50 ms':>9} {'p95 ms':>9} {'max ms':>9} "
          f"{'html KB':>9} {'json KB':>9} {'ratio':>7}  verdict")
    print("-" * 88)

    rows_out = []
    for n in SIZES:
        alerts = make_alerts(n)
        selected = {alerts[i]["id"] for i in range(0, n, 10)}
        ctx = {"alerts": alerts, "selected_ids": selected, "arkime_enabled": True}

        samples = timed(lambda: tpl.render(**ctx), ITERS, WARMUP)
        html = tpl.render(**ctx)
        html_kb = len(html.encode("utf-8")) / 1024.0
        json_kb = len(json.dumps(alerts).encode("utf-8")) / 1024.0

        p50, p95, mx = statistics.median(samples), pct(samples, 95), max(samples)
        verdict = "instant" if p95 < INSTANT_MS else "noticeable"
        print(f"{n:>6} {p50:>9.2f} {p95:>9.2f} {mx:>9.2f} "
              f"{html_kb:>9.1f} {json_kb:>9.1f} {html_kb / json_kb:>7.2f}x  {verdict}")
        rows_out.append((n, p50, p95, html_kb, json_kb))

    print()
    print("Reading this: the p95 column is the ONLY new server cost HTMX adds,")
    print("because the query and the round trip are already paid today. The")
    print("html/json ratio is the extra bytes on the wire, against which the")
    print("client saves parsing the JSON and building the DOM from strings.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
