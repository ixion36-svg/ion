"""Mock TIDE for local integration testing.

TIDE is ION's detection-rule warehouse and the only source of MITRE coverage
(`tide_service.get_global_mitre_coverage`). It is a licensed external service,
so nothing in a dev environment can produce coverage data — which means the
ATT&CK coverage overlay, the single feature the METIS integration exists for,
could not be exercised end to end. This stub closes that gap, in the same
spirit as the other `test-*/` harnesses.

Protocol, read from `src/ion/services/tide_service.py`:

    POST /api/external/query
    header X-TIDE-API-KEY: <key>
    body   {"sql": "...", "client_id": "..."}   ->   {"rows": [...]}

It answers by pattern-matching the SQL rather than parsing it. That is enough
for the coverage path and honest about what it is: a fixture keyed on the
queries ION actually sends, not a SQL engine. When ION grows a new TIDE query
this stub will answer `{"rows": []}` and the caller will read that as "no
data", which is the safe direction.

The fixture is chosen so every coverage state METIS can render appears at
once, against METIS's real rule->technique mappings:

  T1190  5 rules  -> covered   (its 10 METIS rules all read green)
  T1552  4 rules  -> covered   and T1552.001 / .005 roll up to it
  T1078  2 rules  -> partial
  T1505  1 rule   -> partial   and T1505.003 rolls up to it
  T1195  0 rules  -> none      and T1195.002 rolls up to a real gap
  T1610  absent   -> unknown-to-ion (not in the catalogue at all)

The roll-up matters: ION files every rule under the PARENT technique
(`parent = tid.split(".")[0]` in get_global_mitre_coverage), so a
sub-technique is never keyed directly. Rules below are declared on
sub-techniques deliberately, to prove the parent is what comes back.

Usage:
    python test-tide/mock_tide.py            # serves on 127.0.0.1:8500
Then in ION's .env:
    ION_TIDE_ENABLED=true
    ION_TIDE_URL=http://host.docker.internal:8500
    ION_TIDE_API_KEY=mock-key
"""
from __future__ import annotations

import json
import re
from http.server import BaseHTTPRequestHandler, HTTPServer

PORT = 8500

# (rule_id, [technique ids], severity, quality, enabled)
RULES: list[tuple[str, list[str], str, int, int]] = [
    ("rule-web-exploit-1", ["T1190"], "critical", 90, 1),
    ("rule-web-exploit-2", ["T1190"], "high", 80, 1),
    ("rule-web-exploit-3", ["T1190"], "high", 70, 1),
    ("rule-web-exploit-4", ["T1190"], "medium", 60, 1),
    ("rule-web-exploit-5", ["T1190"], "medium", 55, 0),
    # Sub-techniques on purpose: ION rolls these up to T1552.
    ("rule-creds-in-files", ["T1552.001"], "high", 75, 1),
    ("rule-creds-in-registry", ["T1552.002"], "medium", 65, 1),
    ("rule-creds-cloud-inst", ["T1552.005"], "high", 85, 1),
    ("rule-creds-generic", ["T1552"], "medium", 50, 1),
    ("rule-valid-accounts-1", ["T1078"], "high", 70, 1),
    ("rule-valid-accounts-2", ["T1078"], "medium", 60, 0),
    # One rule only -> partial, and T1505.003 rolls up to it.
    ("rule-webshell", ["T1505.003"], "critical", 88, 1),
    # Multi-technique rule, so a rule can count toward two parents.
    ("rule-remote-services", ["T1210", "T1078"], "high", 72, 1),
    ("rule-network-sniffing", ["T1040"], "low", 40, 1),
    ("rule-adversary-in-middle", ["T1557"], "medium", 58, 1),
]

# Techniques the catalogue knows about. T1195 is present with NO rules (a real
# measured gap); T1610/T1611 are absent entirely (unknown-to-ion).
CATALOGUE: list[tuple[str, str, str]] = [
    ("T1005", "Data from Local System", "collection"),
    ("T1040", "Network Sniffing", "credential-access"),
    ("T1059", "Command and Scripting Interpreter", "execution"),
    ("T1078", "Valid Accounts", "defense-evasion"),
    ("T1083", "File and Directory Discovery", "discovery"),
    ("T1189", "Drive-by Compromise", "initial-access"),
    ("T1190", "Exploit Public-Facing Application", "initial-access"),
    ("T1195", "Supply Chain Compromise", "initial-access"),
    ("T1210", "Exploitation of Remote Services", "lateral-movement"),
    ("T1213", "Data from Information Repositories", "collection"),
    ("T1499", "Endpoint Denial of Service", "impact"),
    ("T1505", "Server Software Component", "persistence"),
    ("T1552", "Unsecured Credentials", "credential-access"),
    ("T1555", "Credentials from Password Stores", "credential-access"),
    ("T1556", "Modify Authentication Process", "credential-access"),
    ("T1557", "Adversary-in-the-Middle", "credential-access"),
    ("T1578", "Modify Cloud Compute Infrastructure", "defense-evasion"),
]


def _technique_catalogue() -> list[dict]:
    return [{"technique_id": tid, "name": name, "tactic": tactic}
            for tid, name, tactic in CATALOGUE]


def _rule_stats() -> list[dict]:
    """One row per (technique id as declared on a rule) — ION does the
    parent roll-up itself, so this must NOT pre-aggregate."""
    per: dict[str, dict] = {}
    for rule_id, techniques, severity, quality, enabled in RULES:
        for tid in techniques:
            row = per.setdefault(tid, {
                "technique_id": tid, "rule_count": 0, "_q": [], "enabled_rules": 0,
                "critical_rules": 0, "high_rules": 0, "medium_rules": 0, "low_rules": 0,
            })
            row["rule_count"] += 1
            row["_q"].append(quality)
            row["enabled_rules"] += enabled
            row[f"{severity}_rules"] += 1
    out = []
    for row in per.values():
        quality = row.pop("_q")
        row["avg_quality"] = round(sum(quality) / len(quality), 1)
        out.append(row)
    return sorted(out, key=lambda r: r["technique_id"])


def _rules_listing() -> list[dict]:
    return [{"rule_id": rule_id, "name": rule_id.replace("-", " ").title(),
             "mitre_ids": techniques, "severity": severity,
             "quality_score": quality, "enabled": enabled, "space": "default"}
            for rule_id, techniques, severity, quality, enabled in RULES]


def answer(sql: str) -> list[dict]:
    """Most specific match first. Order matters: the aggregate queries also
    mention `detection_rules`, so a bare substring check on that table name
    would hand them a row listing with none of the columns they read, and
    ION would KeyError on the first row rather than degrade.
    """
    flat = " ".join(sql.split()).lower()

    # `count(DISTINCT rule_id) as total` — one row, one column.
    if "as total" in flat and "count(" in flat:
        return [{"total": len({rule_id for rule_id, *_ in RULES})}]

    # A CTE the posture dashboard builds. Deliberately unanswered: its shape is
    # a moving target and nothing in the METIS integration reads it, so an
    # empty result (ION degrades to "no posture data") beats a wrong one.
    if flat.startswith("with "):
        return []

    # Aggregates over the catalogue, e.g. `(SELECT count(*) FROM
    # mitre_techniques) AS total_techniques`. Must be tested before the plain
    # catalogue read below.
    if "count(" in flat and "from mitre_techniques" in flat:
        rules_with_techniques = {rule_id for rule_id, techniques, *_ in RULES
                                 if techniques}
        return [{"total_techniques": len(CATALOGUE),
                 "total_rules": len({rule_id for rule_id, *_ in RULES}),
                 "covered_techniques": len(rules_with_techniques)}]

    if "from mitre_techniques" in flat:
        return _technique_catalogue()
    if "from detection_rules" in flat and "unnest" in flat:
        return _rule_stats()
    if "from detection_rules" in flat:
        return _rules_listing()
    if re.search(r"select\s+1\b", flat) or "current_timestamp" in flat:
        return [{"ok": 1}]
    return []


class Handler(BaseHTTPRequestHandler):
    def do_POST(self) -> None:  # noqa: N802 - BaseHTTPRequestHandler's contract
        if self.path != "/api/external/query":
            self.send_error(404, "only /api/external/query is mocked")
            return
        if not self.headers.get("X-TIDE-API-KEY"):
            # Real TIDE rejects an unauthenticated query; a stub that does not
            # would hide a missing ION_TIDE_API_KEY.
            self.send_error(401, "X-TIDE-API-KEY required")
            return

        length = int(self.headers.get("Content-Length") or 0)
        try:
            body = json.loads(self.rfile.read(length) or b"{}")
        except json.JSONDecodeError:
            self.send_error(400, "body must be JSON")
            return

        rows = answer(str(body.get("sql", "")))
        payload = json.dumps({"rows": rows, "row_count": len(rows)}).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)
        print(f"  {len(rows):4d} rows  <- {' '.join(str(body.get('sql','')).split())[:90]}",
              flush=True)

    def log_message(self, *args) -> None:
        """Silence the default per-request line; do_POST logs what matters."""


if __name__ == "__main__":
    print(f"Mock TIDE on http://127.0.0.1:{PORT}/api/external/query")
    print(f"  {len(CATALOGUE)} techniques, {len(RULES)} detection rules")
    HTTPServer(("0.0.0.0", PORT), Handler).serve_forever()
