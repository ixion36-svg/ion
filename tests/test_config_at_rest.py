"""config.json is the credential store now, so its mode is load-bearing.

Since v0.99.7 the Elasticsearch, Kibana, Arkime, GitLab, OpenCTI, TIDE, SMTP,
OIDC and response-action credentials live in `$ION_DATA_DIR/.ion/config.json`
in plaintext rather than in `.env`. It was being written 0644 under the usual
umask, so every secret ION holds was world-readable inside the container and in
any backup of the `ion-data` volume.
"""
import json
import os
import stat

import pytest

from ion.core.config import Config

pytestmark = pytest.mark.skipif(
    os.name == "nt", reason="POSIX mode bits; Windows ACLs are not comparable"
)


def _mode(path):
    return stat.S_IMODE(path.stat().st_mode)


def test_new_config_file_is_not_world_readable(tmp_path):
    path = tmp_path / ".ion" / "config.json"
    Config().to_file(path)
    assert _mode(path) == 0o600


def test_an_inherited_0644_file_is_tightened(tmp_path):
    """Upgrades matter more than fresh installs: the file already exists.

    to_file() passes the mode to os.open, which only applies on creation, so
    without the explicit chmod every instance upgraded from v0.99.6 or earlier
    would keep its 0644 file forever.
    """
    path = tmp_path / ".ion" / "config.json"
    Config().to_file(path)
    os.chmod(path, 0o644)
    Config().to_file(path)
    assert _mode(path) == 0o600


def test_the_file_really_does_hold_a_secret(tmp_path):
    """Guards the premise. If secrets stop being serialised here, say so loudly
    rather than leaving two tests enforcing a mode for no reason."""
    path = tmp_path / ".ion" / "config.json"
    config = Config()
    config.elasticsearch_password = "not-a-real-password"
    config.gitlab_token = "not-a-real-token"
    config.to_file(path)
    stored = json.loads(path.read_text(encoding="utf-8"))
    assert stored["elasticsearch_password"] == "not-a-real-password"
    assert stored["gitlab_token"] == "not-a-real-token"


def test_the_mode_is_never_widened_mid_write(tmp_path):
    """0600 must come from the create, not a chmod after the content lands.

    A write-then-chmod leaves a window where the secrets are readable. Checked
    by writing into a directory whose mode would otherwise allow it and
    asserting the file never appears with a wider mode: the only observable
    proof available after the fact is that os.open carried the mode, so assert
    the file was not created by plain open() semantics (0666 & ~umask).
    """
    path = tmp_path / ".ion" / "config.json"
    old_umask = os.umask(0o000)  # would give plain open() a 0666 file
    try:
        Config().to_file(path)
    finally:
        os.umask(old_umask)
    assert _mode(path) == 0o600
