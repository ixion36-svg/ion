from pathlib import Path
import re
import pytest

ROOT=Path(__file__).resolve().parents[2]


#: forensics has been retired into the one build and reaches its rules by
#: page_id; observables still links a sheet of its own.
RETIRED = {'forensics'}


@pytest.mark.parametrize('page',['observables','forensics'])
def test_page_styles_are_scoped_and_external(page):
    source=(ROOT/'src/ion/web/templates'/f'{page}.html').read_text(encoding='utf-8')
    source=re.sub(r'<!--.*?-->','',source,flags=re.S)
    assert '<style' not in source
    if page in RETIRED:
        assert f'/static/css/{page}-page.css' not in source
        assert '{%% block page_id %%}%s{%% endblock %%}' % page in source
    else:
        assert f'/static/css/{page}-page.css' in source
    if page in RETIRED:
        css=(ROOT/'frontend/ion-pages.css').read_text(encoding='utf-8')
    else:
        css=(ROOT/'src/ion/web/static/css'/f'{page}-page.css').read_text(encoding='utf-8')
    assert f'body[data-page="{page}"]' in css
    assert '.ion-fragment-message' in css


@pytest.mark.parametrize('page',['observables','forensics'])
def test_pages_load_shared_fragment_templates_outside_scripts(page):
    source=(ROOT/'src/ion/web/templates'/f'{page}.html').read_text(encoding='utf-8')
    source=re.sub(r'<script\b.*?</script>','',source,flags=re.S)
    assert '{% include "_fragments/ion_fragment_client.html" %}' in source
