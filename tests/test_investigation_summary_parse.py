"""Regression tests for the investigation summary parse fix.

When the model returned a JSON envelope with an EMPTY `summary` field, the
parser used to fall back to `defaults["summary"]` — the raw model content, i.e.
the whole JSON envelope — so the investigation queue displayed
`{"verdict":"","summary":""...}`. The summary must instead fall back to another
narrative field or a clean placeholder, never the raw envelope.
"""

from ion.services.investigation_service import _parse_llm_json


def test_empty_envelope_summary_is_not_raw_json():
    raw = '{"verdict":"","confidence":"","summary":"","key_observations":[]}'
    p = _parse_llm_json(raw)
    assert "{" not in p["summary"]
    assert '"verdict"' not in p["summary"]
    assert p["summary"].strip()  # a clean placeholder, not empty


def test_empty_summary_falls_back_to_analyst_explanation():
    raw = '{"verdict":"true_positive","summary":"","analyst_explanation":"Real detail here."}'
    p = _parse_llm_json(raw)
    assert p["summary"] == "Real detail here."


def test_filled_summary_is_preserved():
    raw = '{"verdict":"false_positive","summary":"Benign vuln scanner.","confidence":"high"}'
    p = _parse_llm_json(raw)
    assert p["summary"] == "Benign vuln scanner."


def test_freeform_non_json_still_uses_content():
    # No JSON envelope at all → the early-return path legitimately keeps the raw
    # prose as the summary (unchanged behaviour).
    p = _parse_llm_json("Just some analyst prose, no json here.")
    assert "prose" in p["summary"].lower()
