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
def test_pcap_cert_and_host_rows_do_not_reference_the_fingerprint_binder(name):
    """The two rows that regressed, pinned by shape rather than by scope analysis."""
    src = (TEMPLATES / "pcap.html").read_text(encoding="utf-8")
    m = re.search(rf"\$\{{{name}\.map\(\s*(\w+)\s*=>(.{{0,1200}}?)</tr>", src, re.S)
    assert m, f"{name}.map row template not found — did the panel move?"
    binder, body = m.group(1), m.group(2)
    stray = {
        v
        for v in re.findall(r"(?<![\w.$])([a-z])\.\w", body)
        if v != binder
    }
    assert not stray, f"{name}.map binds ({binder}) but dereferences {sorted(stray)}"


def test_pcap_carries_no_inline_style_attribute():
    """`data-ion-style=` ends in `style=`; a naive grep counts it as a violation.

    That substring collision is what made the v0.80.0 sweep report 163 violations
    when there were 22. The lookbehind is the whole point of this assertion.
    """
    src = (TEMPLATES / "pcap.html").read_text(encoding="utf-8")
    real = re.findall(r"""(?<![-\w])style\s*=\s*["'][^"']*["']""", src)
    assert not real, f"inline style attributes on /pcap: {real[:5]}"
