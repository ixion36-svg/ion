"""Per-tenant Elasticsearch and Kibana routing.

ION reached one estate through two functions — ``get_elasticsearch_config`` and
``get_kibana_config`` — which roughly thirty ``ElasticsearchService()``
construction sites call on every construction. Overlaying the active tenant
there makes all of them tenant-aware without touching any, and these tests pin
that the overlay actually reaches a constructed service rather than only the
dict.

Two failure modes are worse than an error and so are tested directly:

* a cached service handing one tenant's cluster to another, which reads as a
  working query against the wrong estate;
* an overlay that outlives its scope, so the next unbound caller silently keeps
  talking to a tenant's cluster.
"""

import sys
from pathlib import Path

import httpx
import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))

import ion.services.elasticsearch_service as es_mod  # noqa: E402
from ion.core.config import get_elasticsearch_config, get_kibana_config  # noqa: E402
from ion.core.tenant_context import (  # noqa: E402
    current_tenant_connection,
    tenant_scope,
)
from ion.services.connectors.elasticsearch_connector import (  # noqa: E402
    get_elasticsearch_service,
    reset_elasticsearch_service,
)
from ion.services.elasticsearch_service import ElasticsearchService  # noqa: E402

LEGACY = {
    "es": {
        "url": "https://es-legacy:9200",
        "username": "legacy_u",
        "password": "legacy_p",
        "alert_index": ".alerts-legacy-*",
        "verify_ssl": False,
    },
    "kibana": {"url": "https://kb-legacy:5601", "space_id": "legacy"},
}
MIGRATED = {
    "es": {
        "url": "https://es-new:9200",
        "username": "new_u",
        "password": "new_p",
        "alert_index": ".alerts-prod-*",
        "verify_ssl": False,
    },
    "kibana": {"url": "https://kb-new:5601", "space_id": "production"},
}


@pytest.fixture(autouse=True)
def clean_state():
    reset_elasticsearch_service()
    es_mod._es_pool.clear()
    yield
    reset_elasticsearch_service()
    es_mod._es_pool.clear()


# --------------------------------------------------------------------------
# The overlay.
# --------------------------------------------------------------------------


def test_unbound_requests_use_the_process_config():
    """Every single-estate deploy takes this path and must be unaffected."""
    assert current_tenant_connection() is None
    before = get_elasticsearch_config()
    with tenant_scope(1, connection=LEGACY):
        pass
    assert get_elasticsearch_config() == before


def test_each_tenant_reaches_its_own_cluster():
    with tenant_scope(1, connection=LEGACY):
        assert get_elasticsearch_config()["url"] == "https://es-legacy:9200"
    with tenant_scope(2, connection=MIGRATED):
        assert get_elasticsearch_config()["url"] == "https://es-new:9200"


def test_each_tenant_reaches_its_own_alert_index():
    """The two estates differ by index as well as host, mid-migration."""
    with tenant_scope(1, connection=LEGACY):
        assert get_elasticsearch_config()["alert_index"] == ".alerts-legacy-*"
    with tenant_scope(2, connection=MIGRATED):
        assert get_elasticsearch_config()["alert_index"] == ".alerts-prod-*"


def test_each_tenant_reaches_its_own_kibana_space():
    with tenant_scope(1, connection=LEGACY):
        assert get_kibana_config()["space_id"] == "legacy"
    with tenant_scope(2, connection=MIGRATED):
        assert get_kibana_config()["space_id"] == "production"


def test_kibana_falls_back_to_the_tenants_own_es_credentials():
    """Falling back to the process-wide credentials would point one tenant's
    Kibana client at another estate's login."""
    with tenant_scope(1, connection=LEGACY):
        assert get_kibana_config()["username"] == "legacy_u"
    with tenant_scope(2, connection=MIGRATED):
        assert get_kibana_config()["username"] == "new_u"


def test_keys_a_tenant_does_not_set_are_inherited():
    """A partial tenant must not blank the settings it says nothing about."""
    process = get_elasticsearch_config()
    partial = {"es": {"url": "https://es-partial:9200", "verify_ssl": False}, "kibana": {}}
    with tenant_scope(3, connection=partial):
        merged = get_elasticsearch_config()
    assert merged["url"] == "https://es-partial:9200"
    assert merged["assignment_field"] == process["assignment_field"]
    assert merged["case_index"] == process["case_index"]


def test_the_overlay_does_not_outlive_its_scope():
    with tenant_scope(1, connection=LEGACY):
        assert get_elasticsearch_config()["url"] == "https://es-legacy:9200"
    assert current_tenant_connection() is None
    assert get_elasticsearch_config()["url"] != "https://es-legacy:9200"


def test_the_overlay_is_restored_after_an_exception():
    with pytest.raises(RuntimeError):
        with tenant_scope(1, connection=LEGACY):
            raise RuntimeError("handler blew up")
    assert current_tenant_connection() is None


def test_scopes_nest_without_bleeding():
    with tenant_scope(1, connection=LEGACY):
        with tenant_scope(2, connection=MIGRATED):
            assert get_elasticsearch_config()["url"] == "https://es-new:9200"
        assert get_elasticsearch_config()["url"] == "https://es-legacy:9200"


# --------------------------------------------------------------------------
# The constructed service, not just the dict.
# --------------------------------------------------------------------------


def test_a_constructed_service_talks_to_the_tenants_cluster():
    with tenant_scope(1, connection=LEGACY):
        svc = ElasticsearchService()
        assert svc.url == "https://es-legacy:9200"
        assert svc.alert_index == ".alerts-legacy-*"
        assert svc.is_configured
    with tenant_scope(2, connection=MIGRATED):
        assert ElasticsearchService().url == "https://es-new:9200"


def test_an_explicit_argument_still_wins_over_the_tenant():
    """Callers that pass a URL are asking for that one; admin connection tests do."""
    with tenant_scope(1, connection=LEGACY):
        svc = ElasticsearchService(url="https://es-explicit:9200")
    assert svc.url == "https://es-explicit:9200"


def test_the_cached_service_does_not_leak_across_tenants():
    """A cache here would freeze the first tenant's cluster and serve it to the
    rest — a cross-tenant read from a dozen identical-looking call sites."""
    with tenant_scope(1, connection=LEGACY):
        first = get_elasticsearch_service().url
    with tenant_scope(2, connection=MIGRATED):
        second = get_elasticsearch_service().url
    with tenant_scope(1, connection=LEGACY):
        first_again = get_elasticsearch_service().url

    assert first == "https://es-legacy:9200"
    assert second == "https://es-new:9200", "tenant 1's cluster was served to tenant 2"
    assert first_again == first


def test_single_estate_still_caches():
    """Dropping the cache entirely would cost every single-tenant deploy."""
    assert current_tenant_connection() is None
    assert get_elasticsearch_service() is get_elasticsearch_service()


# --------------------------------------------------------------------------
# The client pool underneath.
# --------------------------------------------------------------------------


def _client_for(conn):
    svc = ElasticsearchService()
    headers = svc._get_headers()
    auth = (svc.username, svc.password) if svc.username and not svc.api_key else None
    return es_mod._get_es_client(headers, auth, False, httpx.Timeout(5.0, connect=1.0))


def test_two_estates_keep_separate_pooled_clients():
    with tenant_scope(1, connection=LEGACY):
        a = _client_for(LEGACY)
    with tenant_scope(2, connection=MIGRATED):
        b = _client_for(MIGRATED)
    with tenant_scope(1, connection=LEGACY):
        a_again = _client_for(LEGACY)

    assert a is not b, "both estates shared one client"
    assert a is a_again, "the other estate's request displaced this client"


def test_alternating_tenants_do_not_grow_the_pool():
    """The single-slot defect showed up as a rebuilt connection pool per request."""
    for _ in range(5):
        with tenant_scope(1, connection=LEGACY):
            _client_for(LEGACY)
        with tenant_scope(2, connection=MIGRATED):
            _client_for(MIGRATED)
    assert len(es_mod._es_pool) == 2


# --------------------------------------------------------------------------
# Shared services stay shared.
# --------------------------------------------------------------------------


def test_arkime_and_opencti_are_not_overlaid():
    """They are estate-wide by decision; a tenant must not redirect them."""
    from ion.core.config import get_arkime_config, get_opencti_config

    with tenant_scope(1, connection=LEGACY):
        arkime_bound = get_arkime_config()
        opencti_bound = get_opencti_config()
    assert arkime_bound == get_arkime_config()
    assert opencti_bound == get_opencti_config()
