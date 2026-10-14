"""Check that CSS differs from the release only by individually approved removals."""

from __future__ import annotations

import hashlib
import json
import subprocess
from pathlib import Path

from dead_css import (
    CLASS_IN_SELECTOR,
    RULE,
    constructed_prefixes,
    corpus_by_kind,
    literal_tokens,
    mask_comments,
    sheet_path,
)

ROOT = Path(__file__).resolve().parents[1]
MANIFEST = ROOT / "docs/dead-css-round-two-2026-10-14.json"


def baseline(path: Path, revision: str) -> str:
    return subprocess.check_output(
        ["git", "show", f"{revision}:{path.relative_to(ROOT).as_posix()}"], cwd=ROOT
    ).decode("utf-8")


def rules(css: str) -> list[dict]:
    result = []
    for match in RULE.finditer(mask_comments(css)):
        selector = match["sel"].strip()
        if "@" in selector:
            continue
        start = match.start("sel") + len(match["sel"]) - len(match["sel"].lstrip())
        result.append({"selector": selector, "start": start, "end": match.end(),
                       "sha256": hashlib.sha256(css[start:match.end()].encode()).hexdigest(),
                       "classes": sorted(set(CLASS_IN_SELECTOR.findall(selector)))})
    return result


def expected(css: str, approved: list[dict]) -> str:
    indexed = {rule["sha256"]: rule for rule in rules(css)}
    removals = []
    for entry in approved:
        rule = indexed[entry["sha256"]]
        assert rule["selector"] == entry["selector"], entry
        removals.append(rule)
    assert len({r["sha256"] for r in removals}) == len(removals)
    for rule in sorted(removals, key=lambda r: r["start"], reverse=True):
        start = rule["start"]
        line_start = css.rfind("\n", 0, start) + 1
        if not css[line_start:start].strip():
            start = line_start
        css = css[:start] + css[rule["end"]:]
    return css


def main() -> None:
    data = json.loads(MANIFEST.read_text(encoding="utf-8"))
    chunks = corpus_by_kind()
    live = literal_tokens("\n".join(chunks.values()))
    prefixes = set().union(*(constructed_prefixes(text, kind=kind)
                             for kind, text in chunks.items()))
    removed = 0
    for sheet, review in data["sheets"].items():
        path = sheet_path(sheet)
        original = baseline(path, data["base"])
        original_rules = {rule["sha256"]: rule for rule in rules(original)}
        candidates = set(review["original_candidate_classes"])
        covered = {key for key, rule in original_rules.items() if set(rule["classes"]) & candidates}
        assert {entry["sha256"] for entry in review["rules"]} == covered, (sheet, "incomplete rule coverage")
        assert len(review["rules"]) == len(covered), (sheet, "duplicate entry")
        for entry in review["rules"]:
            rule = original_rules[entry["sha256"]]
            assert entry["classes"] == rule["classes"], (sheet, entry["selector"], "incorrect class list")
            assert entry["selector"] == rule["selector"], sheet
            if entry["decision"] == "remove":
                assert entry["whole_rule"] and set(rule["classes"]) <= candidates, (sheet, "mixed removal")
                assert not any(pseudo in rule["selector"] for pseudo in (":not(", ":is(", ":where(")), sheet
        approved = [entry for entry in review["rules"] if entry["decision"] == "remove"]
        assert all(entry["decision"] in {"remove", "keep"} and entry["reason"] for entry in review["rules"])
        for entry in approved:
            for name in entry["classes"]:
                assert name not in live, (sheet, name, "now referenced")
                assert not any(name.startswith(prefix) for prefix in prefixes), (sheet, name, "now constructed")
        actual = path.read_text(encoding="utf-8")
        assert actual == expected(original, approved), f"Unapproved CSS change: {sheet}"
        assert actual.count("{") == actual.count("}"), sheet
        removed += len(approved)
        print(f"{sheet}: {len(approved)} approved removals; {len(review['rules']) - len(approved)} candidate rules kept")
    print(f"VERIFIED: {removed} individual removals; all other reviewed stylesheet bytes preserved")


if __name__ == "__main__":
    main()
