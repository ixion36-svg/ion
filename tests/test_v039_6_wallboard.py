"""v0.39.6 — wallboard enhancement: attention state, trend inputs, AI-summary
hygiene (no instruction leakage, no repetition, tight)."""

import ion.services.wallboard_service as wb
from ion.services.wallboard_service import (
    _compute_attention,
    _dedup_sentences,
    _sanitize_landscape_text,
)


# ---------------------------------------------------------------------------
# Attention state — drives the unattended-wall banner + panel glow
# ---------------------------------------------------------------------------
def _alerts(open_n):
    return {"by_status": {"open": open_n}}


def test_attention_ok_when_quiet():
    a = _compute_attention(_alerts(2), {"open_critical": 0, "open_high": 0})
    assert a["level"] == "ok"


def test_attention_critical_on_open_critical_case():
    a = _compute_attention(_alerts(0), {"open_critical": 1, "open_high": 0})
    assert a["level"] == "critical"
    assert "critical" in a["headline"].lower()


def test_attention_warning_on_open_high_case():
    a = _compute_attention(_alerts(0), {"open_critical": 0, "open_high": 3})
    assert a["level"] == "warning"
    assert "high" in a["headline"].lower()


def test_attention_warning_on_backlog(monkeypatch):
    monkeypatch.setenv("ION_WALLBOARD_WARN_BACKLOG", "10")
    a = _compute_attention(_alerts(15), {"open_critical": 0, "open_high": 0})
    assert a["level"] == "warning"
    assert a["open_alert_backlog"] == 15


def test_attention_critical_outranks_warning():
    # an open critical case wins even with a huge backlog
    a = _compute_attention(_alerts(9999), {"open_critical": 2, "open_high": 5})
    assert a["level"] == "critical"


# ---------------------------------------------------------------------------
# AI-summary hygiene — the reported bug: leaks instructions + repeats itself
# ---------------------------------------------------------------------------
def test_summary_strips_instruction_leakage():
    dirty = (
        "Here is the summary:\n"
        "OUTPUT EXACTLY THIS SHAPE:\n"
        "<one short trend bullet>\n"
        "Under 90 words total.\n"
        "As a SOC analyst, I am seeing increased activity.\n"
        "Alert volume is elevated."
    )
    out = _sanitize_landscape_text(dirty)
    for banned in ("Here is", "OUTPUT", "<one short", "Under 90", "As a SOC"):
        assert banned not in out
    assert "Alert volume is elevated." in out


def test_summary_dedups_repeated_lines():
    dirty = "- Brute force up on the VPN.\n- Brute force up on the VPN.\n- Phishing dominates."
    out = _sanitize_landscape_text(dirty)
    assert out.lower().count("brute force up on the vpn") == 1
    assert "Phishing dominates." in out


def test_summary_dedups_repeated_sentences_in_a_line():
    out = _dedup_sentences("X is elevated. X is elevated. Y is calm.")
    assert out.lower().count("x is elevated") == 1
    assert "Y is calm." in out


def test_summary_word_capped_tight():
    out = _sanitize_landscape_text(" ".join(f"word{i}" for i in range(200)))
    assert len(out.split()) <= 86  # 85 + the ellipsis token


def test_summary_empty_in_empty_out():
    assert _sanitize_landscape_text("") == ""


# ---------------------------------------------------------------------------
# Configurable LLM timeout (so slow hosts don't silently lose the summary)
# ---------------------------------------------------------------------------
def test_llm_timeout_env_override(monkeypatch):
    monkeypatch.setenv("ION_WALLBOARD_OLLAMA_TIMEOUT", "45")
    assert wb._wallboard_llm_timeout() == 45.0
    monkeypatch.setenv("ION_WALLBOARD_OLLAMA_TIMEOUT", "not-a-number")
    assert wb._wallboard_llm_timeout() == 15.0  # falls back to default
