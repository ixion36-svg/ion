"""A test module must not read the clock at import.

pytest imports every test module during collection, at the start of the run,
and a module three hours down the list does not execute until three hours in.
A constant assigned at import is therefore as stale as the run is long, and a
row built as "two hours ago" against it is five hours old by the time the code
under test buckets it. Only a full suite is long enough to show this, and the
full suite runs only on a true major, so the fuse is measured in releases:
v0.99.13's run found it in test_ui_fragment_cases after nine 0.x releases.

Where the drift cancels -- the test passes its own constant in as the
reference, or the window is days wide -- the capture is harmless, and those
modules are listed below rather than rewritten. Each entry carries the drift
at which it was measured to break, so the margin is a number and not an
opinion. Anything else reads the clock inside the helper that builds the row.
"""
import ast
import functools
import pathlib

import pytest

TESTS = pathlib.Path(__file__).resolve().parent

# Attribute calls that read the wall clock.
CLOCK_CALLS = {
    ("datetime", "now"), ("datetime", "utcnow"), ("datetime", "today"),
    ("date", "today"), ("time", "time"), ("time", "time_ns"),
    ("time", "monotonic"), ("time", "monotonic_ns"),
}

# Measured with a plugin that shifts each module's import-time constants back
# by N hours, which is what a run of length N does to them. The full suite is
# ~3h20m, so these margins are 29x the exposure and up.
HARMLESS = {
    "test_v047_detection_health.py":
        "windows are 90-365d against rows 1-70d old; breaks only at ~83d drift",
    "test_v055_de_metrics.py":
        "90d trend split at a 45d midpoint, rows at 5d and 70d; breaks at ~83d",
    "test_v056_de_proposals.py":
        "every window is derived from _NOW and passed in, so drift cancels "
        "exactly -- survives 83d",
    "test_v057_de_quirks.py":
        "review dates sit 30d either side of _NOW; breaks at ~83d",
    "test_v058_de_bob.py":
        "90d scorecard window against rows at 5d and 80d; breaks at ~83d",
    "test_v065_traffic_analytics.py":
        "7d daily buckets against rows 1-3d old; breaks at ~4d, the tightest "
        "margin here",
    "test_v097_de_content_pack.py":
        "asserts a refreshed review date is still ahead of _NOW, which drift "
        "only makes truer; breaks at ~83d",
    "unit/test_analyst_efficiency_service.py":
        "_hourly_activity takes NOW as its reference, and the 168h window "
        "holds rows at most 48h old; breaks at ~83d",
}


def _clock_call(node):
    """The clock read inside this expression, or None."""
    for sub in ast.walk(node):
        if not isinstance(sub, ast.Call):
            continue
        func = sub.func
        if not isinstance(func, ast.Attribute):
            continue
        owner = func.value
        name = (owner.attr if isinstance(owner, ast.Attribute)
                else owner.id if isinstance(owner, ast.Name) else None)
        if (name, func.attr) in CLOCK_CALLS:
            return f"{name}.{func.attr}()"
    return None


def _captures(tree):
    """(line, names, call) for every module-level assignment reading the clock.

    Only `tree.body` is walked, so a read inside a function or a fixture --
    which happens at call time and is the fix, not the fault -- is not a hit.
    """
    found = []
    for node in tree.body:
        if isinstance(node, ast.Assign):
            targets = node.targets
        elif isinstance(node, ast.AnnAssign):
            targets = [node.target]
        else:
            continue
        if node.value is None:
            continue
        call = _clock_call(node.value)
        if call is None:
            continue
        names = sorted({n.id for t in targets for n in ast.walk(t)
                        if isinstance(n, ast.Name)})
        found.append((node.lineno, ",".join(names), call))
    return found


@functools.lru_cache(maxsize=1)
def _scan():
    """{relative posix path: [(line, names, call), ...]} over the test tree."""
    out = {}
    for path in sorted(TESTS.rglob("*.py")):
        tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
        hits = _captures(tree)
        if hits:
            out[path.relative_to(TESTS).as_posix()] = hits
    return out


def test_the_detector_sees_a_capture_and_ignores_a_call_time_read():
    """Without this the suite below passes by detecting nothing at all."""
    captured = ast.parse(
        "import datetime\nNOW = datetime.datetime.now()\n")
    assert _captures(captured), "a module-level clock read must be a hit"

    deferred = ast.parse(
        "import datetime\ndef _now():\n    return datetime.datetime.now()\n")
    assert not _captures(deferred), "a read inside a function is the fix"

    annotated = ast.parse(
        "import datetime\nNOW: datetime.datetime = datetime.datetime.utcnow()\n")
    assert _captures(annotated), "an annotated assignment is still a capture"

    derived = ast.parse(
        "import time\nSTAMP = str(int(time.time())) + '-x'\n")
    assert _captures(derived), "a clock read nested in an expression counts"


def test_the_scan_actually_reaches_the_test_tree():
    """A path bug here would empty the result and report a clean sweep."""
    files = list(TESTS.rglob("*.py"))
    assert len(files) > 300, (
        f"only {len(files)} test files found under {TESTS} -- the scan is "
        "looking in the wrong place, and an empty scan passes every assertion")


@pytest.mark.parametrize("module", sorted(HARMLESS))
def test_each_allowed_capture_is_still_there(module):
    """An allowlist entry that no longer applies is a licence nobody revoked."""
    path = TESTS / module
    assert path.exists(), f"{module} is allowlisted but no longer exists"
    assert module in _scan(), (
        f"{module} no longer captures the clock at import -- drop its "
        "allowlist entry rather than leaving the exemption standing")


def test_no_other_test_module_captures_the_clock_at_import():
    offenders = {path: hits for path, hits in _scan().items()
                 if path not in HARMLESS}
    assert not offenders, "\n".join(
        [""] + [f"  {path}:{line}  {names} = ...{call}"
                for path, hits in sorted(offenders.items())
                for line, names, call in hits]
        + ["",
           "Read the clock in the helper that builds the row, not at module",
           "level. pytest imports this file at collection; a full suite does",
           "not reach it for hours, and the constant is stale by that much.",
           "If the drift provably cancels, add it to HARMLESS with the drift",
           "at which it was measured to break."])
