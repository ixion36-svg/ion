"""ION's VEX documents, and the rules that stop them asserting nonsense.

A VEX document is a security claim about the product. The failure that matters
is not a crash: it is a document that ships, parses, and says something ION
cannot support — an unjustified `not_affected`, or a statement for an advisory
nobody ruled on.

The CSAF output is checked against OASIS's own JSON schema rather than against
this file's reading of the prose spec, with the schema and the three CVSS
schemas it references bundled under security/schemas so the check runs
offline like everything else here.
"""

from __future__ import annotations

import json
import re
import subprocess
import sys
from pathlib import Path

import pytest

_ROOT = Path(__file__).resolve().parent.parent
_SOURCE = _ROOT / "security" / "vex_statements.yaml"
_OPENVEX = _ROOT / "security" / "ion.openvex.json"
_CSAF = _ROOT / "security" / "ion.csaf.json"
_SCHEMAS = _ROOT / "security" / "schemas"
_GENERATOR = _ROOT / "scripts" / "generate_vex.py"
_PYPROJECT = _ROOT / "pyproject.toml"

sys.path.insert(0, str(_ROOT / "scripts"))

_ADVISORY_RE = re.compile(r"\b(?:CVE|PYSEC|MAL|GHSA)-[A-Za-z0-9-]+\b")


def _openvex() -> dict:
    return json.loads(_OPENVEX.read_text(encoding="utf-8"))


def _csaf() -> dict:
    return json.loads(_CSAF.read_text(encoding="utf-8"))


# --------------------------------------------------------------------------
# CSAF, against the published schema
# --------------------------------------------------------------------------

def test_csaf_validates_against_the_oasis_schema():
    """The one check that is not this file's opinion."""
    # Imported, not importorskip'd. jsonschema is a declared dev dependency,
    # and a skip here would turn the only external check of this document into
    # a silent pass on any machine that happened not to have it.
    import jsonschema.validators
    from referencing import Registry, Resource

    schema = json.loads(
        (_SCHEMAS / "csaf_json_schema.json").read_text(encoding="utf-8"))

    # The CSAF schema $refs three FIRST CVSS schemas by URL. Bundled and
    # mapped here so validation never reaches the network.
    resources = []
    for version in ("2.0", "3.0", "3.1"):
        path = _SCHEMAS / f"cvss-v{version}.json"
        resources.append((
            f"https://www.first.org/cvss/cvss-v{version}.json",
            Resource.from_contents(json.loads(path.read_text(encoding="utf-8"))),
        ))
    registry = Registry().with_resources(resources)

    validator_cls = jsonschema.validators.validator_for(schema)
    validator = validator_cls(schema, registry=registry)
    errors = sorted(validator.iter_errors(_csaf()), key=lambda e: list(e.path))
    assert not errors, "\n".join(
        f"{list(e.path)}: {e.message}" for e in errors[:10])


def test_csaf_declares_the_vex_profile():
    doc = _csaf()["document"]
    assert doc["category"] == "csaf_vex"
    assert doc["csaf_version"] == "2.0"


def test_csaf_names_one_product_carrying_the_ion_version():
    version = _ion_version()
    names = _csaf()["product_tree"]["full_product_names"]
    assert len(names) == 1
    helper = names[0]["product_identification_helper"]
    assert version in helper["cpe"]
    assert version in helper["purls"][0]


# --------------------------------------------------------------------------
# OpenVEX structure
# --------------------------------------------------------------------------

def test_openvex_carries_every_required_document_field():
    doc = _openvex()
    for field in ("@context", "@id", "author", "timestamp", "version",
                  "statements"):
        assert field in doc, f"OpenVEX requires {field}"
    assert doc["statements"]


def test_every_statement_has_a_vulnerability_a_product_and_a_status():
    for s in _openvex()["statements"]:
        assert s["vulnerability"]["name"]
        assert s["products"]
        assert s["status"] in (
            "not_affected", "affected", "fixed", "under_investigation")


def test_not_affected_always_carries_a_legal_justification():
    """An unjustified not_affected is an unsupported security claim."""
    import generate_vex

    for s in _openvex()["statements"]:
        if s["status"] == "not_affected":
            assert s.get("justification") in generate_vex.JUSTIFICATIONS, (
                f"{s['vulnerability']['name']} claims not_affected without a "
                f"justification a consumer would recognise"
            )


def test_affected_statements_say_what_to_do():
    for s in _openvex()["statements"]:
        if s["status"] == "affected":
            assert s.get("action_statement")


def test_no_advisory_is_stated_twice():
    names = [s["vulnerability"]["name"] for s in _openvex()["statements"]]
    assert len(names) == len(set(names))


# --------------------------------------------------------------------------
# Drift: the documents against the pins they describe
# --------------------------------------------------------------------------

def _ion_version() -> str:
    m = re.search(r'^version\s*=\s*"([^"]+)"',
                  _PYPROJECT.read_text(encoding="utf-8"), re.MULTILINE)
    assert m
    return m.group(1)


def test_every_advisory_named_in_pyproject_has_a_statement():
    """The guard that keeps the pin and the assertion together.

    A security pin added with a comment naming its advisory, and no VEX
    statement, means the shipped document is silently incomplete: a scanner
    gets no answer for that CVE and the omission looks exactly like a CVE
    nobody has found yet.
    """
    in_pyproject = set(_ADVISORY_RE.findall(
        _PYPROJECT.read_text(encoding="utf-8")))
    stated = {s["vulnerability"]["name"] for s in _openvex()["statements"]}
    missing = sorted(in_pyproject - stated)
    assert not missing, (
        f"pyproject.toml names these advisories with no VEX statement: "
        f"{missing}. Add them to security/vex_statements.yaml and re-run "
        f"scripts/generate_vex.py."
    )


def test_the_documents_describe_the_current_ion_version():
    version = _ion_version()
    assert version in _openvex()["statements"][0]["products"][0]["@id"]
    assert _csaf()["document"]["tracking"]["id"].endswith(version)


def test_the_committed_documents_are_not_stale():
    """`--check` regenerates and compares, so an edited source that was never
    regenerated fails here rather than shipping."""
    result = subprocess.run(
        [sys.executable, str(_GENERATOR), "--check"],
        capture_output=True, text=True, cwd=str(_ROOT),
    )
    assert result.returncode == 0, (
        f"VEX documents are stale — run scripts/generate_vex.py\n"
        f"{result.stdout}{result.stderr}"
    )


# --------------------------------------------------------------------------
# The generator refuses malformed input
# --------------------------------------------------------------------------

def _source_with(statement: dict) -> dict:
    import yaml
    source = yaml.safe_load(_SOURCE.read_text(encoding="utf-8"))
    source["statements"] = [statement]
    return source


def test_generator_refuses_not_affected_without_a_justification():
    import generate_vex

    with pytest.raises(SystemExit, match="justification"):
        generate_vex.validate(_source_with({
            "vulnerability": "CVE-2026-0001", "status": "not_affected",
        }))


def test_generator_refuses_an_invented_justification():
    import generate_vex

    with pytest.raises(SystemExit, match="justification"):
        generate_vex.validate(_source_with({
            "vulnerability": "CVE-2026-0002", "status": "not_affected",
            "justification": "we had a look and it seemed fine",
        }))


def test_generator_refuses_an_unknown_status():
    import generate_vex

    with pytest.raises(SystemExit, match="status"):
        generate_vex.validate(_source_with({
            "vulnerability": "CVE-2026-0003", "status": "probably_ok",
        }))


def test_generator_refuses_affected_without_an_action():
    import generate_vex

    with pytest.raises(SystemExit, match="action_statement"):
        generate_vex.validate(_source_with({
            "vulnerability": "CVE-2026-0004", "status": "affected",
        }))


def test_generator_refuses_two_statuses_for_one_advisory():
    import generate_vex

    source = _source_with({"vulnerability": "CVE-2026-0005", "status": "fixed"})
    source["statements"].append(
        {"vulnerability": "CVE-2026-0005", "status": "under_investigation"})
    with pytest.raises(SystemExit, match="twice"):
        generate_vex.validate(source)
