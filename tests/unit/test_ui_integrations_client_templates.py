from pathlib import Path
import re

import pytest
from jinja2 import DictLoader, Environment

PAGE = Path(__file__).resolve().parents[2] / 'src/ion/web/templates/integrations.html'


@pytest.mark.parametrize('identifier', ['topology-service-node', 'flow-stage-template', 'flow-arrow-template', 'flow-controls-template', 'flow-legend-item'])
def test_topology_client_templates_are_real_markup(identifier):
    source = re.sub(r'<script\b.*?</script>', '', PAGE.read_text(encoding='utf-8'), flags=re.S)
    assert '<template id="' + identifier + '"' in source


@pytest.mark.parametrize('identifier', ['topology-service-node', 'flow-stage-template', 'flow-controls-template'])
def test_client_templates_survive_jinja_inheritance(identifier):
    environment = Environment(loader=DictLoader({
        'page.html': PAGE.read_text(encoding='utf-8'),
        'base.html': '{% block content %}{% endblock %}{% block scripts %}{% endblock %}',
        '_fragments/ion_fragment_client.html': '',
    }))
    user = type('Viewer', (), {'has_permission': lambda self, permission: False})()
    rendered = environment.get_template('page.html').render(current_user=user)
    assert '<template id="' + identifier + '"' in rendered


def test_topology_states_are_server_read_and_client_geometry_uses_nodes():
    source = PAGE.read_text(encoding='utf-8')
    topology = source[source.index('function createServiceNodes()'):]
    assert '.innerHTML' not in topology
    assert "ionLoadFragment('/ui/integrations/topology'" in topology
    assert 'createElementNS' in topology
    assert "cloneTemplate('flow-stage-template')" in topology
