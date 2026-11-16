"""The removal proof must reject incomplete or misleading audit records."""

import json
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "tools"))

from tools import check_dead_css_vetting as proof  # noqa: E402


@pytest.fixture
def reviewed_sheet(tmp_path, monkeypatch):
    original = "    .gone {color:red}\n.live {color:blue}\n"
    rule = proof.rules(original)[0]
    entry = {key: value for key, value in rule.items() if key not in {"start", "end"}}
    entry.update(decision="remove", reason="No source producer", whole_rule=True)
    data = {"base": "release", "sheets": {"example.css": {
        "original_candidate_classes": ["gone"], "rules": [entry],
    }}}
    manifest = tmp_path / "review.json"
    sheet = tmp_path / "example.css"
    sheet.write_text(proof.expected(original, [entry]), encoding="utf-8")
    monkeypatch.setattr(proof, "MANIFEST", manifest)
    monkeypatch.setattr(proof, "baseline", lambda *_: original)
    monkeypatch.setattr(proof, "sheet_path", lambda _: sheet)
    monkeypatch.setattr(proof, "corpus", lambda: '<div class="live"></div>')

    def run():
        manifest.write_text(json.dumps(data), encoding="utf-8")
        proof.main()

    return data, sheet, run


def test_accepts_only_the_approved_removal(reviewed_sheet, capsys):
    _, sheet, run = reviewed_sheet
    run()
    assert sheet.read_text(encoding="utf-8") == "\n.live {color:blue}\n"
    assert "VERIFIED: 1 individual removals" in capsys.readouterr().out


def test_empty_class_list_cannot_bypass_reachability(reviewed_sheet):
    data, _, run = reviewed_sheet
    data["sheets"]["example.css"]["rules"][0]["classes"] = []
    with pytest.raises(AssertionError, match="incorrect class list"):
        run()


def test_missing_rule_record_is_not_complete_coverage(reviewed_sheet):
    data, _, run = reviewed_sheet
    data["sheets"]["example.css"]["rules"] = []
    with pytest.raises(AssertionError, match="incomplete rule coverage"):
        run()


def test_unapproved_change_to_a_retained_rule_fails(reviewed_sheet):
    _, sheet, run = reviewed_sheet
    sheet.write_text(".live {color:red}\n", encoding="utf-8")
    with pytest.raises(AssertionError, match="Unapproved CSS change"):
        run()


def test_new_source_reference_blocks_a_formerly_dead_removal(reviewed_sheet, monkeypatch):
    _, _, run = reviewed_sheet
    monkeypatch.setattr(proof, "corpus", lambda: '<div class="gone"></div>')
    with pytest.raises(AssertionError, match="now referenced"):
        run()
