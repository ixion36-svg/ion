from pathlib import Path
import re
import subprocess
import sys

import pytest

ROOT = Path(__file__).resolve().parents[2]


def test_team_calendar_renderers_use_dom_nodes():
    source = (ROOT / 'src/ion/web/templates/training.html').read_text(encoding='utf-8')
    region = source.split('async function loadTeamData()', 1)[1].split('// Permission-based tab visibility', 1)[0]
    region = re.sub(r'/\*[\s\S]*?\*/|//[^\n]*', '', region)
    assert '.innerHTML' not in region
    assert 'trainingRender(' in region


def test_client_templates_live_outside_scripts():
    path = ROOT / 'src/ion/web/templates/_fragments/training_client_nodes.html'
    assert path.exists()
    source = path.read_text(encoding='utf-8')
    assert '<template id="training-node-' in source
    assert '<script' not in source
    assert 'data-args=' not in source or 'ION_SLOT_' not in source


def test_node_renderer_uses_text_and_clone_contract():
    path = ROOT / 'src/ion/web/static/js/training-nodes.js'
    assert path.exists()
    source = path.read_text(encoding='utf-8')
    assert 'cloneTemplate(value)' in source
    assert 'text.textContent = String(items)' in source
    assert '.innerHTML' not in source


def test_training_client_renders_data_empty_failure_and_zero():
    assert (ROOT / 'src/ion/web/static/js/training-nodes.js').exists()
    pytest.importorskip('playwright.sync_api')
    result = subprocess.run([sys.executable, str(ROOT / 'tools/_training_smoke.py')], cwd=ROOT, text=True, capture_output=True)
    if 'Executable doesn\'t exist' in result.stderr or 'Chromium distribution' in result.stderr:
        pytest.skip('Edge browser is unavailable on this host')
    assert result.returncode == 0, result.stdout + result.stderr
