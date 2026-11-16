"""One severity table for every door an alert comes through.

Defect: the alias table written out once per caller. The Elasticsearch
normaliser and the webhook receiver each had a copy, and nothing held them to
the same answer.
"""
from __future__ import annotations

import re
from pathlib import Path

import pytest

from ion.core.severity import SEVERITIES, normalize_severity

SRC = Path(__file__).resolve().parents[2] / "src" / "ion"


@pytest.mark.parametrize("sent, expected", [
    ("critical", "critical"), ("crit", "critical"), ("1", "critical"), (1, "critical"),
    ("high", "high"), ("2", "high"),
    ("medium", "medium"), ("med", "medium"), ("warning", "medium"), ("3", "medium"),
    ("low", "low"), ("4", "low"),
    ("info", "info"), ("informational", "info"), ("5", "info"),
    ("  HIGH ", "high"),
])
def test_known_names_and_numbers_map_to_a_rendered_severity(sent, expected):
    assert normalize_severity(sent) == expected


@pytest.mark.parametrize("sent", ["", "sev-0", "<img src=x>", None, "6"])
def test_anything_unrecognised_becomes_the_default(sent):
    assert normalize_severity(sent) == "medium"
    assert normalize_severity(sent, default="low") == "low"


def test_every_answer_is_a_severity_the_queue_renders():
    for sent in ("1", "2", "3", "4", "5", "crit", "med", "warning", "informational", "nonsense"):
        assert normalize_severity(sent) in SEVERITIES


def test_no_caller_keeps_its_own_copy_of_the_alias_table():
    """`"crit": "critical"` beside a numeric alias is the table's signature.
    The investigation parser has a `crit` alias too, but for model output and
    without the numbers, so it is a different table and is not matched."""
    for path in SRC.rglob("*.py"):
        if path.name == "severity.py":
            continue
        source = path.read_text(encoding="utf-8")
        assert not re.search(r'"1":\s*"critical"', source), path
