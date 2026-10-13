from pathlib import Path
import re

ROOT = Path(__file__).resolve().parents[2]


def test_training_styles_are_compiled_and_themed():
    source = (ROOT / 'src/ion/web/templates/training.html').read_text(encoding='utf-8')
    source = re.sub(r'<!--.*?-->', '', source, flags=re.S)
    assert not re.search(r'<style\b', source)
    stylesheet = (ROOT / 'frontend/ion-training.css').read_text(encoding='utf-8')
    assert 'body[data-page="training"]' in stylesheet
    assert '.training-header' in stylesheet
    assert 'var(--text-bright)' in stylesheet

