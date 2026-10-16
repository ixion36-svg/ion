from pathlib import Path
import re
import pytest

ROOT=Path(__file__).resolve().parents[2]


@pytest.mark.parametrize('page',['observables','forensics'])
def test_page_styles_are_scoped_and_external(page):
    source=(ROOT/'src/ion/web/templates'/f'{page}.html').read_text(encoding='utf-8')
    source=re.sub(r'<!--.*?-->','',source,flags=re.S)
    assert '<style' not in source
    assert f'/static/css/{page}-page.css' in source
    css=(ROOT/'src/ion/web/static/css'/f'{page}-page.css').read_text(encoding='utf-8')
    assert f'body[data-page="{page}"]' in css
    assert '.ion-fragment-message' in css


@pytest.mark.parametrize('page',['observables','forensics'])
def test_pages_load_shared_fragment_templates_outside_scripts(page):
    source=(ROOT/'src/ion/web/templates'/f'{page}.html').read_text(encoding='utf-8')
    source=re.sub(r'<script\b.*?</script>','',source,flags=re.S)
    assert '{% include "_fragments/ion_fragment_client.html" %}' in source
