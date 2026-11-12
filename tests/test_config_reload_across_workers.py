"""A settings save reaches every web worker, not only the one that handled it.

Each uvicorn worker is a process with its own cached configuration. A save
rewrites config.json and reloads the worker that served it; the other three
kept the old values until a restart. Found while previewing the SSVC inputs:
the vulnerability table showed old decisions on three requests in four.

Each worker now compares config.json's mtime and size with what it loaded,
at most every RELOAD_CHECK_SECONDS. These tests stand in for "another
worker" by writing the file directly, as that worker's save would.
"""

from __future__ import annotations

import json
import os
import threading

import pytest

import ion.core.config as config_module
from ion.core.config import Config, get_config, set_config


def _write(path, data, bump=0):
    path.write_text(json.dumps(data), encoding="utf-8")
    if bump:
        st = path.stat()
        os.utime(path, ns=(st.st_atime_ns, st.st_mtime_ns + bump))


@pytest.fixture
def cfg_file(tmp_path, monkeypatch):
    monkeypatch.setenv("ION_DATA_DIR", str(tmp_path))
    monkeypatch.delenv("ION_KIBANA_URL", raising=False)
    monkeypatch.delenv("ION_SSVC_EXPOSURE", raising=False)
    monkeypatch.setattr(config_module, "RELOAD_CHECK_SECONDS", 0.0)
    path = tmp_path / ".ion" / "config.json"
    path.parent.mkdir()
    _write(path, {"kibana_url": "http://old:5601", "ssvc_exposure": "controlled"})
    set_config(None)
    yield path
    set_config(None)


def test_a_change_saved_by_another_worker_is_picked_up(cfg_file):
    first = get_config()
    assert first.kibana_url == "http://old:5601"
    _write(cfg_file, {"kibana_url": "http://new:5601", "ssvc_exposure": "open"}, bump=10_000_000)
    second = get_config()
    assert second is not first
    assert second.kibana_url == "http://new:5601"
    assert second.ssvc_exposure == "open"


def test_an_unchanged_file_keeps_the_same_object(cfg_file):
    assert get_config() is get_config()


def test_no_check_inside_the_interval(cfg_file, monkeypatch):
    monkeypatch.setattr(config_module, "RELOAD_CHECK_SECONDS", 3600.0)
    first = get_config()
    _write(cfg_file, {"kibana_url": "http://new:5601"}, bump=10_000_000)
    assert get_config() is first


def test_the_environment_still_outranks_the_file_after_a_reload(cfg_file, monkeypatch):
    monkeypatch.setenv("ION_KIBANA_URL", "http://env:5601")
    assert get_config().kibana_url == "http://env:5601"
    _write(cfg_file, {"kibana_url": "http://new:5601"}, bump=10_000_000)
    assert get_config().kibana_url == "http://env:5601"


def test_a_configuration_set_by_a_caller_is_not_replaced(cfg_file):
    pinned = Config(kibana_url="http://pinned:5601")
    set_config(pinned)
    _write(cfg_file, {"kibana_url": "http://new:5601"}, bump=10_000_000)
    assert get_config() is pinned


def test_a_deleted_file_reloads_to_defaults_not_a_crash(cfg_file):
    get_config()
    cfg_file.unlink()
    assert get_config().kibana_url == Config().kibana_url


def test_readers_never_see_a_half_built_configuration(cfg_file, monkeypatch):
    """The loader applies environment overrides one by one; a reload builds
    a separate object and swaps it in whole, so no reader catches it midway."""
    monkeypatch.setenv("ION_KIBANA_URL", "http://env:5601")
    get_config()
    seen = set()
    stop = threading.Event()

    def read():
        while not stop.is_set():
            seen.add(get_config().kibana_url)

    readers = [threading.Thread(target=read) for _ in range(4)]
    for r in readers:
        r.start()
    for i in range(60):
        _write(cfg_file, {"kibana_url": f"http://file{i}:5601"}, bump=(i + 1) * 10_000_000)
        get_config()
    stop.set()
    for r in readers:
        r.join()
    assert seen == {"http://env:5601"}


def test_an_unreadable_file_keeps_the_settings_in_force(cfg_file):
    first = get_config()
    cfg_file.write_text("{ half a document", encoding="utf-8")
    assert get_config() is first


def test_a_save_never_leaves_a_partial_file(tmp_path):
    """to_file swaps a finished file into place instead of truncating."""
    path = tmp_path / ".ion" / "config.json"
    Config(kibana_url="http://a:5601").to_file(path)
    seen_bad = []
    stop = threading.Event()

    def read():
        while not stop.is_set():
            try:
                json.loads(path.read_text(encoding="utf-8"))
            except PermissionError:
                pass  # Windows: the swap holds the name for an instant
            except ValueError:
                seen_bad.append(1)

    reader = threading.Thread(target=read)
    reader.start()
    for i in range(40):
        Config(kibana_url=f"http://s{i}:5601").to_file(path)
    stop.set()
    reader.join()
    assert seen_bad == []
    assert not list(path.parent.glob(".config.json.*.tmp"))
