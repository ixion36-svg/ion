"""The three hashed-class losses the rewrite harness is red on.

Each one is a different kind of loss, and a test that only asked the harness
to go green would accept a `replaced_by` claim naming a selector that does
not paint. These pin the destination, and each one names a case the rule
must not match.
"""
from __future__ import annotations

import json
import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SHEETS = ROOT / "src/ion/web/static/css"
TPL = ROOT / "src/ion/web/templates"
MAP = ROOT / "tools/hashed_class_map.json"

EVENT_SELECTOR = 'body[data-page="data_flow"] .df-winlog-row .df-event-id'
TITLE_SELECTOR = 'body[data-page="maturity"] .mat-title'


def _sheets() -> str:
    return "\n".join(
        p.read_text(encoding="utf-8", errors="replace")
        for p in sorted(SHEETS.glob("*.css"))
    )


def _code(css: str) -> str:
    return re.sub(r"/\*.*?\*/", "", css, flags=re.S)


def _rules() -> dict:
    data = json.loads(MAP.read_text(encoding="utf-8"))
    return data.get("rules", data)


def _rule_body(css: str, selector: str) -> str:
    body = _code(css)
    match = re.search(re.escape(selector) + r"\s*\{([^}]*)\}", body)
    assert match, selector
    return re.sub(r"\s+", "", match.group(1))


def test_the_event_id_weight_beats_the_generic_value_and_the_others_stay_600():
    """`._ion-s-92fb99917f` is `font-weight:900`, and it loses to
    `body[data-page=data_flow] .df-winlog-row .val{font-weight:600}` in the
    compiled sheet: that rule is one element, one attribute and two classes.
    A one-class replacement loses the same way, so the destination has to
    be that specific, and it has to be the Event ID only.
    """
    sheet = (SHEETS / "data-flow-page.css").read_text(encoding="utf-8")
    body = _rule_body(sheet, EVENT_SELECTOR)
    assert "font-weight:900" in body

    # The generic value rule is not restated at 900. Doing that would make
    # Keywords and Task Category heavy too, which the mock-up did not.
    assert not re.search(
        r"\.df-winlog-row \.val\s*\{[^}]*font-weight:\s*900",
        _code(sheet),
    )

    fragment = (TPL / "_fragments/data_flow_panels.html").read_text(encoding="utf-8")
    assert 'class="val df-event-id">4728<' in fragment
    assert fragment.count("df-event-id") == 1
    assert "_ion-s-92fb99917f" not in fragment
    assert 'class="val">Audit Success<' in fragment

    claim = _rules()["_ion-s-92fb99917f"]["replaced_by"]
    assert claim == [EVENT_SELECTOR]
    assert EVENT_SELECTOR in _sheets()
    page = (TPL / "data_flow.html").read_text(encoding="utf-8")
    assert "data-flow-page.css" in page


def test_the_activity_bar_height_survived_as_a_hook_and_not_as_css():
    """`_ion-s-9ce2eb0cde` declared `height:${pct}%`. That is the literal
    JavaScript, which no browser applies. The height came back as
    data-ion-style on `.ae-activity-bar`. Putting the interpolation into a
    stylesheet again would be the original defect.
    """
    entry = _rules()["_ion-s-9ce2eb0cde"]
    assert entry["css"] == "height:${pct}%;"
    assert any("JS-concatenated" in item for item in entry["unmapped"])
    assert "replaced_by" not in entry

    fragment = (TPL / "_fragments/executive_report_team.html").read_text(encoding="utf-8")
    assert 'class="ae-activity-bar" data-ion-style="height:{{ row.pct }}%"' in fragment
    assert "_ion-s-9ce2eb0cde" not in fragment

    assert "._ion-s-9ce2eb0cde" not in _code(_sheets())
    assert "${pct}" not in _code(_sheets())


def test_the_maturity_title_keeps_its_input_rule_and_the_notes_do_not():
    """`_ion-s-56b5cc5749` was the assessment-title `<input>`. The control
    is still `#mat-title`. daisyUI's `.input` paints a different control;
    these eight declarations are the ones that left.
    """
    sheet = (SHEETS / "maturity-page.css").read_text(encoding="utf-8")
    body = _rule_body(sheet, TITLE_SELECTOR)
    for declaration in (
        "flex:1",
        "background:var(--bg-secondary)",
        "border:1px solid var(--ion-border)",
        "color:var(--text-primary)",
        "padding:8px 12px",
        "border-radius:var(--radius)",
        "font:inherit",
        "font-size:.85rem",
    ):
        assert declaration.replace(" ", "") in body, declaration

    fragment = (TPL / "_fragments/maturity_questionnaire.html").read_text(encoding="utf-8")
    title = re.search(r"<input\b[^>]*id=\"mat-title\"[^>]*>", fragment)
    assert title, "the title input"
    assert "mat-title" in title.group(0).split("id=")[0]
    notes = re.search(r"<input\b[^>]*id=\"mat-notes-\{\{ q\.id \}\}\"[^>]*>", fragment, re.S)
    assert notes, "the notes input"
    assert "mat-title" not in notes.group(0)

    claim = _rules()["_ion-s-56b5cc5749"]["replaced_by"]
    assert claim == [TITLE_SELECTOR]
    assert TITLE_SELECTOR in _sheets()
    page = (TPL / "maturity.html").read_text(encoding="utf-8")
    assert "maturity-page.css" in page
