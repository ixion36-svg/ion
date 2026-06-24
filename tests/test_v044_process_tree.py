"""v0.44.0 — alert-local process explorer tree builder.

`build_process_tree` normalises an ES alert ``_source`` into an ordered
root→leaf process chain (grandparent → parent → alert process) with the
alert's own process flagged, and reports the true ancestry depth from
``process.Ext.ancestry`` even when intermediate processes aren't named.
"""
from ion.services.elasticsearch_service import build_process_tree


def test_full_chain_ordered_with_alert_flagged():
    src = {
        "process.parent.parent.name": "explorer.exe",
        "process.parent.parent.pid": 1000,
        "process.parent.name": "cmd.exe",
        "process.parent.pid": 2000,
        "process.name": "powershell.exe",
        "process.pid": 3000,
        "process.command_line": "powershell -enc ZQBjAGgAbwA=",
        "user.name": "victim",
    }
    tree = build_process_tree(src)
    assert tree["available"] is True
    roles = [n["role"] for n in tree["nodes"]]
    assert roles == ["grandparent", "parent", "alert"]
    # levels are top→bottom
    assert [n["level"] for n in tree["nodes"]] == [0, 1, 2]
    leaf = tree["nodes"][-1]
    assert leaf["is_alert"] is True
    assert leaf["name"] == "powershell.exe"
    assert leaf["user"] == "victim"  # alert process inherits top-level user


def test_parent_and_alert_only():
    src = {"process.name": "evil.exe", "process.parent.name": "winword.exe"}
    tree = build_process_tree(src)
    assert [n["role"] for n in tree["nodes"]] == ["parent", "alert"]
    assert tree["nodes"][0]["name"] == "winword.exe"


def test_ancestry_depth_and_truncated_count():
    # 4 real ancestors per Ext.ancestry, but only the parent is named in the doc
    src = {
        "process.name": "mimikatz.exe",
        "process.parent.name": "cmd.exe",
        "process.Ext.ancestry": ["e1", "e2", "e3", "e4"],
    }
    tree = build_process_tree(src)
    assert tree["ancestry_depth"] == 4
    # 1 named ancestor (parent) → 3 earlier ancestors not in the alert doc
    assert tree["truncated_ancestors"] == 3


def test_no_process_context_unavailable():
    tree = build_process_tree({"source.ip": "10.0.0.1", "destination.ip": "10.0.0.2"})
    assert tree["available"] is False
    assert tree["nodes"] == []


def test_executable_basename_fallback_for_name():
    src = {"process.executable": "C:\\Windows\\System32\\rundll32.exe", "process.pid": 42}
    tree = build_process_tree(src)
    assert tree["nodes"][-1]["name"] == "rundll32.exe"


def test_nested_source_shape_supported():
    src = {
        "process": {
            "name": "bash",
            "pid": 7,
            "parent": {"name": "sshd", "pid": 3},
        }
    }
    tree = build_process_tree(src)
    assert [n["role"] for n in tree["nodes"]] == ["parent", "alert"]
    assert tree["nodes"][0]["name"] == "sshd"
    assert tree["nodes"][-1]["name"] == "bash"


def test_none_source_safe():
    assert build_process_tree(None)["available"] is False
