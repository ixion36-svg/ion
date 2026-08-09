"""LLM JSON-parse robustness.

Foundation-Sec wraps its JSON in ```json fences and sprinkles `//` line comments
(e.g. `"techniques": [...] // Assuming ...`) and sometimes trailing commas — all
invalid JSON, so the parser fell back to dumping the raw envelope into `summary`.
Comments must be stripped **string-aware** so real URLs (`http://...`) survive.
"""
from ion.services.investigation_service import _parse_llm_json

FENCED_WITH_COMMENTS = '''```json
{
  "verdict": "true_positive",
  "severity": "high",
  "summary": "Encoded PowerShell download cradle to http://192.168.1.100/a.ps1",
  "mitre": {
    "tactics": ["Execution"],
    "techniques": ["T1059.001", "T1105"]  // Assuming download cradle
  },
  "recommended_actions": ["Isolate the host",],
}
```
Some trailing model commentary that is not JSON.'''


def test_parses_fenced_json_with_line_comments():
    p = _parse_llm_json(FENCED_WITH_COMMENTS)
    assert p["verdict"] == "true_positive"
    assert p["severity"] == "high"
    # summary is the real field, NOT the raw envelope dumped in
    assert p["summary"].startswith("Encoded PowerShell")
    assert "{" not in p["summary"]


def test_url_inside_string_not_corrupted_by_comment_strip():
    p = _parse_llm_json(FENCED_WITH_COMMENTS)
    assert "http://192.168.1.100/a.ps1" in p["summary"]


def test_techniques_survive_trailing_comment():
    p = _parse_llm_json(FENCED_WITH_COMMENTS)
    techs = p.get("mitre", {}).get("techniques", [])
    assert "T1059.001" in techs and "T1105" in techs


def test_trailing_commas_tolerated():
    # Parse must succeed (summary is the real field, not the raw envelope dumped
    # in). Verdict is normalised to ION's canonical vocab, so just check parsing.
    p = _parse_llm_json('{"verdict":"benign","summary":"ok","recommended_actions":["a",],}')
    assert p["summary"] == "ok"
    assert "benign" in p["verdict"]


def test_plain_valid_json_still_parses():
    p = _parse_llm_json('{"verdict":"false_positive","severity":"low","summary":"clean"}')
    assert p["verdict"] == "false_positive"
    assert p["summary"] == "clean"
