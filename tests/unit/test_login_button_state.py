"""The sign-in button's busy state.

The button used to save its own `innerHTML`, replace it with the string
"Signing in…" and put it back. Both labels ship in the markup now and the
handler toggles `hidden`.

This is the unauthenticated entry point, so the test that matters is that
the button comes back usable after a refusal. A login page that strands its
own button is worse than one that writes to innerHTML, and the drive at
scratchpad/login_drive.py is what proved it in a browser: thirteen checks
including a real sign-in and a real refusal.
"""
from __future__ import annotations

import re
from pathlib import Path

import ion.web

PAGE = Path(ion.web.__file__).parent / "templates" / "login.html"


def _page() -> str:
    return PAGE.read_text(encoding="utf-8")


def _script() -> str:
    """Only the script body, so a rule about code cannot pass on markup."""
    blocks = re.findall(r"<script[^>]*>(.*?)</script>", _page(), re.S)
    assert blocks, "the page has no inline script, so these tests are stale"
    return "\n".join(blocks)


def test_the_button_state_is_not_written_as_markup():
    """The defect. `loginBtn.innerHTML = 'Signing in…'` put the one piece of
    text on this page that no stylesheet and no reader of the template could
    see into a string in a script."""
    js = _script()
    assert ".innerHTML" not in js, (
        "the sign-in page assigns or reads innerHTML again"
    )
    assert "insertAdjacentHTML" not in js and ".outerHTML" not in js


def test_both_labels_ship_in_the_markup():
    page = _page()
    assert "data-login-label" in page and "data-login-busy" in page
    # The busy one hidden at rest, or the button says both things at once.
    busy = re.search(r"<span[^>]*data-login-busy[^>]*>", page)
    assert busy, "the busy label is gone"
    assert "hidden" in busy.group(0), "the busy label ships visible"


def test_the_icon_is_not_in_the_swapped_text():
    """Why textContent is not the fix either. The arrow lives inside the
    button, so assigning text to the button would delete it, and the restore
    would put it back: a flicker on the one page that must look dependable.
    Only the label spans are toggled, so the icon is never touched."""
    page = _page()
    button = re.search(r"<button[^>]*id=\"login-btn\".*?</button>", page, re.S)
    assert button, "the sign-in button moved or was renamed"
    assert button.group(0).count("<svg") == 1
    label = re.search(r"data-login-label[^>]*>([^<]*)<", button.group(0))
    assert label and "svg" not in label.group(1)


def test_the_busy_state_is_set_and_cleared_through_one_function():
    """Two call sites set this state and they used to be four assignments.
    A `finally` that forgot one left the button disabled with the idle label
    showing, which reads as a page that has stopped responding."""
    js = _script()
    assert "function setBusy(" in js
    assert js.count("setBusy(true)") == 1
    assert js.count("setBusy(false)") == 1
    # And the clear is in a finally, so a thrown error cannot strand it.
    tail = js[js.index("setBusy(true)"):]
    finally_at = tail.find("finally")
    clear_at = tail.find("setBusy(false)")
    assert finally_at != -1 and finally_at < clear_at, (
        "the busy state is cleared outside a finally, so a request that "
        "throws leaves the button disabled for good"
    )
