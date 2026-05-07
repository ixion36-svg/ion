"""Round-trip tests for the SKILL.md publisher.

Strategy (London School TDD):
- ``render_skill_md`` is a pure function; drive it with constructed
  ``AlertPromptTemplate`` instances (no DB needed).
- Round-trip: render → write to tmp dir → ``_load_skill_from_file`` → assert
  the loaded ``Skill`` has correct name, triggers, and body.
- Additional unit tests cover frontmatter structure, slug generation, and
  handling of edge-case inputs (no techniques, no rule groups, etc.).
"""

from __future__ import annotations

import io
import json
import zipfile
from pathlib import Path

import types

import pytest

from ion.services.skill_publisher_service import _slug, render_skill_md
from ion.services.skill_loader import _load_skill_from_file


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _make_template(**kwargs) -> types.SimpleNamespace:
    """Build a duck-typed AlertPromptTemplate substitute for unit tests.

    ``render_skill_md`` only reads plain attributes — it never calls ORM
    machinery — so a SimpleNamespace works perfectly and avoids the overhead
    of a real DB fixture.
    """
    defaults = {
        "id": 1,
        "name": "Test Rule Prompt",
        "description": "Detects suspicious lateral movement via SMB.",
        "enabled": True,
        "rule_ids_json": json.dumps(["rule-smb-lateral-001"]),
        "rule_groups_json": json.dumps(["endpoint", "lateral_movement"]),
        "rule_id_pattern": None,
        "mitre_techniques_json": json.dumps(["T1021", "T1021.002"]),
        "mitre_tactics_json": json.dumps(["lateral-movement"]),
        "priority": 50,
        "prompt_text": (
            "# SMB Lateral Movement\n\n"
            "Investigate the source host for credential reuse and pivot paths.\n"
        ),
        "investigation_checklist_text": None,
        "severity_hint": None,
        "expected_outputs_json": None,
        "created_by_id": None,
    }
    defaults.update(kwargs)
    return types.SimpleNamespace(**defaults)


# ---------------------------------------------------------------------------
# Slug generation
# ---------------------------------------------------------------------------


class TestSlug:
    def test_spaces_become_hyphens(self):
        assert _slug("Test Rule Prompt") == "test-rule-prompt"

    def test_special_chars_stripped(self):
        assert _slug("Windows/LOLBin (T1218)") == "windows-lolbin-t1218"

    def test_already_lowercase(self):
        assert _slug("endpoint-recon") == "endpoint-recon"

    def test_leading_trailing_hyphens_stripped(self):
        assert _slug("  lateral movement  ") == "lateral-movement"


# ---------------------------------------------------------------------------
# render_skill_md — frontmatter structure
# ---------------------------------------------------------------------------


class TestRenderSkillMd:
    def test_returns_tuple_of_str_and_dict(self):
        tmpl = _make_template()
        result = render_skill_md(tmpl)
        assert isinstance(result, tuple) and len(result) == 2
        md, extras = result
        assert isinstance(md, str)
        assert isinstance(extras, dict)

    def test_no_supporting_files_by_default(self):
        tmpl = _make_template()
        _, extras = render_skill_md(tmpl)
        assert extras == {}

    def test_starts_with_frontmatter_fence(self):
        tmpl = _make_template()
        md, _ = render_skill_md(tmpl)
        assert md.startswith("---\n")

    def test_name_is_slugified(self):
        tmpl = _make_template(name="My Fancy Template")
        md, _ = render_skill_md(tmpl)
        assert "name: my-fancy-template" in md

    def test_description_present(self):
        tmpl = _make_template(description="Short description here.")
        md, _ = render_skill_md(tmpl)
        assert "Short description here." in md

    def test_techniques_in_matches_techniques(self):
        tmpl = _make_template(mitre_techniques_json=json.dumps(["T1021", "T1078"]))
        md, _ = render_skill_md(tmpl)
        assert "  - T1021" in md
        assert "  - T1078" in md

    def test_empty_techniques_falls_back_to_any(self):
        tmpl = _make_template(mitre_techniques_json=None)
        md, _ = render_skill_md(tmpl)
        assert "  - any" in md

    def test_rule_groups_in_matches_rule_groups(self):
        tmpl = _make_template(rule_groups_json=json.dumps(["endpoint", "sysmon"]))
        md, _ = render_skill_md(tmpl)
        assert "  - endpoint" in md
        assert "  - sysmon" in md

    def test_tactic_tags_prefixed(self):
        tmpl = _make_template(mitre_tactics_json=json.dumps(["lateral-movement"]))
        md, _ = render_skill_md(tmpl)
        assert "  - tactic:lateral-movement" in md

    def test_ion_template_tag_always_present(self):
        tmpl = _make_template()
        md, _ = render_skill_md(tmpl)
        assert "  - ion-template" in md

    def test_prompt_text_in_body(self):
        tmpl = _make_template(prompt_text="## My investigation body\nDo this first.")
        md, _ = render_skill_md(tmpl)
        assert "## My investigation body" in md
        assert "Do this first." in md

    def test_rule_id_in_when_to_use(self):
        tmpl = _make_template(rule_ids_json=json.dumps(["elastic-smb-001"]))
        md, _ = render_skill_md(tmpl)
        assert "elastic-smb-001" in md

    def test_rule_id_pattern_in_when_to_use(self):
        tmpl = _make_template(rule_id_pattern="^windows\\.lateral\\.")
        md, _ = render_skill_md(tmpl)
        assert "^windows\\.lateral\\." in md


# ---------------------------------------------------------------------------
# Round-trip: render → write to disk → load via skill_loader
# ---------------------------------------------------------------------------


class TestRoundTrip:
    def test_loaded_skill_name_matches_slug(self, tmp_path: Path):
        tmpl = _make_template(name="SMB Lateral Movement")
        md, _ = render_skill_md(tmpl)

        skill_dir = tmp_path / "smb-lateral-movement"
        skill_dir.mkdir()
        skill_file = skill_dir / "SKILL.md"
        skill_file.write_text(md, encoding="utf-8")

        skill = _load_skill_from_file(skill_file)
        assert skill is not None
        assert skill.name == "smb-lateral-movement"

    def test_loaded_skill_has_correct_techniques(self, tmp_path: Path):
        tmpl = _make_template(
            name="process-injection-hunt",
            mitre_techniques_json=json.dumps(["T1055", "T1055.012"]),
        )
        md, _ = render_skill_md(tmpl)

        skill_dir = tmp_path / "process-injection-hunt"
        skill_dir.mkdir()
        (skill_dir / "SKILL.md").write_text(md, encoding="utf-8")

        skill = _load_skill_from_file(skill_dir / "SKILL.md")
        assert skill is not None
        assert "T1055" in skill.matches_techniques
        assert "T1055.012" in skill.matches_techniques

    def test_loaded_skill_has_correct_rule_groups(self, tmp_path: Path):
        tmpl = _make_template(
            name="endpoint-recon",
            rule_groups_json=json.dumps(["endpoint", "discovery"]),
        )
        md, _ = render_skill_md(tmpl)

        skill_dir = tmp_path / "endpoint-recon"
        skill_dir.mkdir()
        (skill_dir / "SKILL.md").write_text(md, encoding="utf-8")

        skill = _load_skill_from_file(skill_dir / "SKILL.md")
        assert skill is not None
        assert "endpoint" in skill.matches_rule_groups
        assert "discovery" in skill.matches_rule_groups

    def test_loaded_skill_body_matches_prompt_text(self, tmp_path: Path):
        body = "# Checklist\n\n1. Check parent process.\n2. Pivot to Sysmon.\n"
        tmpl = _make_template(name="body-check", prompt_text=body)
        md, _ = render_skill_md(tmpl)

        skill_dir = tmp_path / "body-check"
        skill_dir.mkdir()
        (skill_dir / "SKILL.md").write_text(md, encoding="utf-8")

        skill = _load_skill_from_file(skill_dir / "SKILL.md")
        assert skill is not None
        assert "Check parent process." in skill.body
        assert "Pivot to Sysmon." in skill.body

    def test_empty_techniques_round_trips_as_any(self, tmp_path: Path):
        tmpl = _make_template(name="any-technique-skill", mitre_techniques_json=None)
        md, _ = render_skill_md(tmpl)

        skill_dir = tmp_path / "any-technique-skill"
        skill_dir.mkdir()
        (skill_dir / "SKILL.md").write_text(md, encoding="utf-8")

        skill = _load_skill_from_file(skill_dir / "SKILL.md")
        assert skill is not None
        assert "any" in skill.matches_techniques


# ---------------------------------------------------------------------------
# ZIP output shape (no FastAPI client needed — test service layer directly)
# ---------------------------------------------------------------------------


class TestZipShape:
    def _make_zip_from_template(self, tmpl: AlertPromptTemplate) -> zipfile.ZipFile:
        from ion.services.skill_publisher_service import _slug
        import io, zipfile as zf_mod

        skill_md, extras = render_skill_md(tmpl)
        folder_name = _slug(tmpl.name)
        buf = io.BytesIO()
        with zf_mod.ZipFile(buf, mode="w") as zf:
            zf.writestr(f"{folder_name}/SKILL.md", skill_md.encode("utf-8"))
            for rel_path, data in extras.items():
                zf.writestr(f"{folder_name}/{rel_path}", data)
        buf.seek(0)
        return zf_mod.ZipFile(buf, "r")

    def test_zip_contains_skill_md(self):
        tmpl = _make_template(name="zip-test")
        zf = self._make_zip_from_template(tmpl)
        names = zf.namelist()
        assert "zip-test/SKILL.md" in names

    def test_skill_md_in_zip_round_trips(self, tmp_path: Path):
        tmpl = _make_template(name="zip-round-trip", prompt_text="Hunt for evil.\n")
        zf = self._make_zip_from_template(tmpl)

        extract_dir = tmp_path / "extracted"
        zf.extractall(extract_dir)
        skill_file = extract_dir / "zip-round-trip" / "SKILL.md"
        assert skill_file.exists()

        skill = _load_skill_from_file(skill_file)
        assert skill is not None
        assert skill.name == "zip-round-trip"
        assert "Hunt for evil." in skill.body
