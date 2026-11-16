"""The startup log must redact the DSN credential, not the host.

``docker-entrypoint.sh`` printed ``${ION_DATABASE_URL%@*}@***``, which strips
from the last ``@`` -- keeping the password and hiding the host, the reverse of
the intent -- so every container start wrote the database password to its log.

This runs the entrypoint's redaction region under ``sh`` rather than reading it
as source. A source-reading assertion here would match the explanatory comment
beside the code instead of the code, and pass against the leaking form.
"""

import re
import shutil
import subprocess
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
ENTRYPOINT = ROOT / "docker-entrypoint.sh"

# The redaction sits between the "Waiting for database..." banner and the
# python probe. Bounding the region by those two fixed lines means a revert to
# the one-line form is still extracted and still executed -- and then fails on
# the password assertions, rather than silently extracting nothing and passing.
_REGION = re.compile(
    r'echo "Waiting for database\.\.\."\n(.*?)\npython -c', re.DOTALL
)

SH = shutil.which("sh")

pytestmark = pytest.mark.skipif(SH is None, reason="no POSIX shell available")


def _redaction_snippet() -> str:
    text = ENTRYPOINT.read_text(encoding="utf-8")
    match = _REGION.search(text)
    assert match, "could not locate the startup-log region in docker-entrypoint.sh"
    return match.group(1)


def _run(dsn: str) -> str:
    result = subprocess.run(
        [SH, "-c", _redaction_snippet()],
        env={"ION_DATABASE_URL": dsn, "PATH": "/usr/bin:/bin"},
        capture_output=True,
        text=True,
        timeout=30,
    )
    assert result.returncode == 0, result.stderr
    return result.stdout


def test_the_password_is_not_printed():
    out = _run("postgresql://ion:ion2025@postgres:5432/ion")
    assert "ion2025" not in out


def test_the_host_is_still_printed():
    # The leaking form hid the host behind *** while printing the credential.
    # Losing the host makes the line useless for diagnosing a wrong target.
    out = _run("postgresql://ion:ion2025@postgres:5432/ion")
    assert "postgres:5432/ion" in out


def test_the_username_is_still_printed():
    out = _run("postgresql://ion:ion2025@postgres:5432/ion")
    assert "ion:***" in out


def test_a_password_containing_an_at_sign_is_redacted():
    # Splitting on the first @ would print everything after it, password and
    # all. The DSN must be split on its last @.
    out = _run("postgresql://ion:p@ss@postgres:5432/ion")
    assert "p@ss" not in out
    assert "postgres:5432/ion" in out


def test_a_dsn_with_no_credential_is_left_alone():
    # Asserted on the whole line, not a substring: the leaking form appended
    # a bare "@***" to a DSN that had no credential to redact, which a
    # containment check could not tell apart from correct output.
    out = _run("postgresql://postgres:5432/ion")
    assert out.strip() == "URL: postgresql://postgres:5432/ion"


def test_a_dsn_with_a_user_but_no_password_is_left_alone():
    out = _run("postgresql://ion@postgres:5432/ion")
    assert "ion@postgres:5432/ion" in out


def test_no_credential_survives_any_shape():
    for dsn, secret in (
        ("postgresql://ion:ion2025@postgres:5432/ion", "ion2025"),
        ("postgresql://ion:p@ss@postgres:5432/ion", "p@ss"),
        ("postgresql://admin:hunter2@db.internal:5432/ion", "hunter2"),
    ):
        assert secret not in _run(dsn), dsn
