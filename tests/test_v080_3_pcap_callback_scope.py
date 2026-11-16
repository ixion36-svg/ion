"""A render callback must not dereference a variable it does not bind.

/pcap shipped `certs.map(c => ... f.known_malware ...)` and the same for
`hosts.map(h => ...)`. `f` is the binder of the *fingerprint* tables above, copied
down. It threw `ReferenceError: f is not defined` — but only for a capture that
actually contained TLS certificates or host profiles, so an empty-ish PCAP looked
fine and the panels simply never rendered.

These are shape assertions on the two panels that regressed, NOT general scope
analysis. A scope-based version was written and deliberately discarded: it accepted
`f` because `f` is bound in a SIBLING callback higher up the file, so it passed on
the broken code, and without that allowance it flagged 24 legitimate closures over
outer variables. A heuristic that misses the real bug and invents two dozen false
ones is worse than no test. Catching this class generally needs a real JS parser.
"""
import re
from pathlib import Path

import pytest

TEMPLATES = Path(__file__).resolve().parents[1] / "src" / "ion" / "web" / "templates"

@pytest.mark.parametrize("name", ["certs", "hosts"])
def test_pcap_cert_and_host_rows_are_built_server_side(name):
    """The hazard this file was written for is now unreachable.

    It was a `.map` callback dereferencing `f`, a variable bound in a
    SIBLING callback higher up the file. The header above says why a
    general scope check was discarded: it accepted `f` for exactly that
    reason, so it passed on the broken code, and without the allowance it
    flagged 24 legitimate closures. Catching the class needed a real JS
    parser.

    It does not need one now. Both panels are server-rendered, from
    cert_rows and host_rows in ui/pcap.py, and a Jinja `{% for %}` scopes
    its loop variable to its own block. There is no sibling callback to
    close over, so the bug cannot be written rather than merely being
    absent.

    Both builders return None rather than an empty list when the payload
    is not a list, which is the other half of the original report: an
    empty-ish PCAP looked fine because a failed read and a capture with no
    certificates in it were the same answer.
    """
    module = (Path(__file__).resolve().parents[1] / "src" / "ion" / "web"
              / "ui" / "pcap.py").read_text(encoding="utf-8")
    builder = {"certs": "cert_rows", "hosts": "host_rows"}[name]
    assert f"def {builder}(" in module
    fn = module[module.index(f"def {builder}("):]
    fn = fn[:fn.index("\ndef ", 1)]
    assert "if not isinstance(raw, list):" in fn
    assert "return None" in fn, \
        "a failed read must not read as a capture with none of these"


def test_no_row_template_is_built_from_a_map_callback_any_more():
    """The shape that produced the bug, gone from the page.

    The `.map(` calls left in pcap.html build vis.js DataSets and a list
    of checkbox indices, and two of the five are inside comments. None
    assembles a table row, so none can close over the wrong binder.
    """
    src = (TEMPLATES / "pcap.html").read_text(encoding="utf-8")
    code = re.sub(r"^\s*//.*$", "", src, flags=re.M)
    rows = re.findall(r"\.map\(\s*\w+\s*=>[^;]{0,1200}?</tr>", code, re.S)
    assert rows == [], rows


def test_pcap_carries_no_inline_style_attribute():
    """`data-ion-style=` ends in `style=`; a naive grep counts it as a violation.

    That substring collision is what made the v0.80.0 sweep report 163 violations
    when there were 22. The lookbehind is the whole point of this assertion.
    """
    src = (TEMPLATES / "pcap.html").read_text(encoding="utf-8")
    real = re.findall(r"""(?<![-\w])style\s*=\s*["'][^"']*["']""", src)
    assert not real, f"inline style attributes on /pcap: {real[:5]}"
