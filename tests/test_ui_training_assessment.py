"""Browser-owned assessment and career markup must use inert shell templates."""
import pathlib
import re
import json
import shutil
import subprocess

import pytest

PAGE = pathlib.Path(__file__).resolve().parents[1] / "src/ion/web/templates/training.html"


@pytest.mark.parametrize("name", ["rmInit", "rmShowRolePicker", "rmRenderQuestionnaire", "rmRenderResult", "rmShowHistory", "crInit", "crShowDetail"])
def test_browser_renderers_do_not_parse_html(name):
    text = PAGE.read_text(encoding="utf-8")
    body = re.search(r"(?:async )?function " + name + r"\([^)]*\) \{(.*?)(?=\n(?:async )?function |\n</script>)", text, re.S).group(1)
    assert "innerHTML" not in body
    assert "rmTemplate" in body or "rmMessage" in body


@pytest.mark.parametrize("template_id", ["training-rm-message", "training-rm-role", "training-rm-questionnaire", "training-rm-result", "training-rm-history", "training-cr-domain", "training-cr-cert", "training-cr-detail"])
def test_shell_templates_exist_outside_scripts(template_id):
    text = re.sub(r"<script\b.*?</script>", "", PAGE.read_text(encoding="utf-8"), flags=re.S)
    include = PAGE.parent / "_fragments/training_assessment_client.html"
    assert "{% include '_fragments/training_assessment_client.html' %}" in text
    text += include.read_text(encoding="utf-8")
    assert f'<template id="{template_id}">' in text


def test_role_match_reads_preserve_refusal_state():
    text = PAGE.read_text(encoding="utf-8")
    start = text.index("async function rmInit()")
    end = text.index("function rmStartAssessment", start)
    body = text[start:end]
    assert "if (!r.ok)" in body
    assert "Failed to load assessment" in body
    assert "No roles available" in body


@pytest.mark.parametrize("name,payload,ok,expected", [
    ("rmInit", {"detail": "Forbidden"}, False, "Failed to load assessment. Please try again."),
    ("rmInit", {}, True, "Failed to load assessment. Please try again."),
    ("rmInit", {"assessment": None}, True, "picker"),
    ("rmInit", {"assessment": {"overall_match_pct": 0}}, True, "result:0"),
    ("rmShowRolePicker", {"roles": []}, True, "No roles available."),
    ("rmShowRolePicker", {}, True, "Failed to load roles"),
    ("rmShowRolePicker", {"roles": []}, False, "Failed to load roles"),
    ("rmShowHistory", {"assessments": []}, True, 'No assessments yet — click "Start Assessment" above.'),
    ("rmShowHistory", {}, True, "Failed to load history"),
    ("rmShowHistory", {"assessments": []}, False, "Failed to load history"),
])
def test_role_match_read_outcomes_in_javascript(name, payload, ok, expected):
    node = shutil.which("node")
    if not node:
        pytest.skip("Node.js is required to execute browser read logic")
    text = PAGE.read_text(encoding="utf-8")
    function = re.search(r"async function " + name + r"\([^)]*\) \{.*?(?=\n(?:async )?function |\n</script>)", text, re.S).group(0)
    script = """
const events = [];
const RM_API = '/api/skills/role-match';
let rmDefinitions;
const document = {getElementById: () => ({})};
function rmMessage(message) { events.push(message); }
function rmShowRolePicker() { events.push('picker'); }
function rmRenderResult(assessment) { events.push('result:' + assessment.overall_match_pct); }
"""
    # The picker stub is needed only for rmInit; avoid redeclaring the target.
    if name == "rmShowRolePicker":
        script = script.replace("function rmShowRolePicker() { events.push('picker'); }", "")
    script += "\nconst fetch = async () => ({ok: " + json.dumps(ok) + ", json: async () => (" + json.dumps(payload) + ")});\n"
    script += function + "\n" + name + "().then(() => console.log(JSON.stringify(events.at(-1))));"
    result = subprocess.run([node, "-e", script], capture_output=True, text=True, check=True, encoding="utf-8")
    assert json.loads(result.stdout) == expected
