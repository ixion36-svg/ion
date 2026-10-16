from pathlib import Path
import re

ROOT = Path(__file__).resolve().parents[2]


def test_detection_engineering_styles_are_compiled():
    text = (ROOT / 'src/ion/web/templates/detection_engineering.html').read_text(encoding='utf-8')
    assert '<style' not in re.sub(r'<!--.*?-->', '', text, flags=re.S)
    assert '{% block page_id %}detection-engineering{% endblock %}' in text
    css = (ROOT / 'frontend/ion-detection-engineering.css').read_text(encoding='utf-8')
    assert 'body[data-page="detection-engineering"] .de-panel.active' in css
    assert 'color:#fff' not in css


def test_detection_engineering_has_no_runtime_html_string_writes():
    source = (ROOT / 'src/ion/web/templates/detection_engineering.html').read_text(encoding='utf-8')
    source = re.sub(r'/\*.*?\*/|//[^\n]*|<!--.*?-->', '', source, flags=re.S)
    assert not re.search(r'innerHTML\s*\+?=|insertAdjacentHTML|outerHTML\s*\+?=', source)


def test_detection_engineering_loading_and_badge_templates_are_outside_scripts():
    source = (ROOT / 'src/ion/web/templates/detection_engineering.html').read_text(encoding='utf-8')
    shell = re.sub(r'<script\b.*?</script>', '', source, flags=re.S)
    assert '{% include "_fragments/detection_engineering_client.html" %}' in shell
    fragment = (ROOT / 'src/ion/web/templates/_fragments/detection_engineering_client.html').read_text(encoding='utf-8')
    assert '<template id="de-loading-template">' in fragment
    assert '<template id="de-badge-template">' in fragment
    assert '<script' not in fragment
