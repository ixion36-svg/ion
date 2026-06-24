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


# ── full events-index analyzer (assemble_full_process_tree) ──────────────────
from ion.services.elasticsearch_service import assemble_full_process_tree  # noqa: E402


def _ev(eid, name, parent=None, pid=None):
    d = {"process.entity_id": eid, "process.name": name}
    if parent:
        d["process.parent.entity_id"] = parent
    if pid:
        d["process.pid"] = pid
    return d


def test_full_tree_resolves_named_ancestry_and_children():
    alert = {
        "process.entity_id": "P3",
        "process.name": "powershell.exe",
        "process.Ext.ancestry": ["P2", "P1"],  # parent-first
    }
    events = [
        _ev("P1", "explorer.exe"),
        _ev("P2", "cmd.exe", parent="P1"),
        _ev("P3", "powershell.exe", parent="P2"),
        _ev("P4", "evil.exe", parent="P3"),   # child of the alert process
        _ev("P9", "unrelated.exe", parent="PX"),
    ]
    tree = assemble_full_process_tree(alert, events)
    assert tree["available"] is True
    assert tree["mode"] == "events-index"
    # root → … → alert, named from the events index
    assert [n["name"] for n in tree["nodes"]] == ["explorer.exe", "cmd.exe", "powershell.exe"]
    assert [n["role"] for n in tree["nodes"]] == ["ancestor", "ancestor", "alert"]
    assert tree["nodes"][-1]["is_alert"] is True
    assert tree["truncated_ancestors"] == 0
    # direct child attached one level below the alert process
    assert [c["name"] for c in tree["children"]] == ["evil.exe"]
    assert tree["children"][0]["level"] == tree["nodes"][-1]["level"] + 1


def test_full_tree_counts_unresolved_ancestors():
    alert = {
        "process.entity_id": "P3",
        "process.name": "rundll32.exe",
        "process.Ext.ancestry": ["P2", "P1", "P0"],
    }
    # only P2 resolves; P1 and P0 are not in the events index
    events = [_ev("P2", "cmd.exe", parent="P1"), _ev("P3", "rundll32.exe", parent="P2")]
    tree = assemble_full_process_tree(alert, events)
    assert [n["name"] for n in tree["nodes"]] == ["cmd.exe", "rundll32.exe"]
    assert tree["truncated_ancestors"] == 2


def test_full_tree_falls_back_to_alert_parent_chain_without_ancestry():
    alert = {
        "process.entity_id": "P3",
        "process.name": "mshta.exe",
        "process.parent.name": "winword.exe",
    }
    tree = assemble_full_process_tree(alert, [])
    assert [n["role"] for n in tree["nodes"]] == ["parent", "alert"]
    assert tree["children"] == []

