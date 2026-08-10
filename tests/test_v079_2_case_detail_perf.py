"""v0.79.2 — the /cases alert detail stops fetching the same document three times,
fills in Host/User, and the healthcheck stops flapping at boot.

**The slowness.** v0.77.0 replaced the tab layout (one section loaded) with the
stacked one (every section open). Three of those sections want the SAME
document: Fields, Raw Data, and — on /cases — the rule guide. They start
together, so each checks the `raw_data` cache, finds it empty, and issues its
own Elasticsearch fetch. One request per alert click became three, on the
critical path of every selection. Measured after the fix: 1.

**The blank Host/User.** `/api/cases/{id}` returns a thin per-alert projection —
es_alert_id, rule_name, status, priority, observables, mitre_techniques,
analyst_notes — built for the old narrow slide-out that showed a rule name and
little else. v0.77.0 pointed a full-detail component at it, so Host, User,
Source, Timestamp and the message rendered blank on a case while /alerts (which
gets the whole Elasticsearch document) filled them in.

Widening the case API would not fix it: ION's own tables do not hold host/user
either — `alert_triage` has no such columns, that data lives in Elasticsearch.
So the component hydrates the blanks from the /raw document it already fetches,
which costs no extra request precisely because of the coalescing above.

**The healthcheck.** Boot runs migrations plus ~12 advisory-locked seeders
before the workers answer anything. A 10-15s start period is not enough, and a
probe landing during seeding plus real traffic exceeded the 5s timeout and was
killed — which left the container "unhealthy" and stopped ion-seeder, whose
dependency is `condition: service_healthy`.
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest

JS = Path("src/ion/web/static/js/alert-detail.js")
CASES = Path("src/ion/web/templates/cases.html")
COMPOSE = Path("docker-compose.yml")
DOCKERFILE = Path("Dockerfile")


def _strip_comments(js: str) -> str:
    """A comment describing a fetch is not a fetch. (Sixth time this session.)"""
    js = re.sub(r"/\*.*?\*/", "", js, flags=re.S)
    return re.sub(r"^\s*//.*$", "", js, flags=re.M)


@pytest.fixture(scope="module")
def component() -> str:
    return _strip_comments(JS.read_text(encoding="utf-8"))


@pytest.fixture(scope="module")
def cases_js() -> str:
    html = CASES.read_text(encoding="utf-8")
    js = "\n".join(re.findall(r"<script(?![^>]*\bsrc=)[^>]*>(.*?)</script>", html, re.S))
    return _strip_comments(js)


# ── one /raw request per alert, not three ────────────────────────────────


def test_there_is_a_single_coalescing_raw_fetcher(component):
    assert "function fetchRawOnce(" in component
    assert "_rawInflight" in component


def test_every_consumer_goes_through_it(component, cases_js):
    """FOUR places want this document — Fields, the stacked Raw Data section,
    the tab-click Raw Data loader, and the /cases rule guide. Each issuing its
    own request is the regression, so the guard is the count of direct `/raw`
    fetches, not of alert fetches in general (related, sequence and
    auto-investigate are different endpoints and belong where they are).

    An earlier version of this test counted all alert-endpoint fetches, which
    is how the tab-click loader was found still bypassing the coalescer.
    """
    # The URL is built by string concatenation across lines, so match the
    # endpoint fragment rather than a `fetch(` call shape. Exactly one place in
    # the whole component may construct this URL: fetchRawOnce.
    raw_urls = re.findall(r"/raw", component)
    assert len(raw_urls) == 1, (
        f"{len(raw_urls)} places construct the /raw URL — "
        "every consumer must share fetchRawOnce"
    )

    assert "fetchRawOnce(alert.id)" in component, "Raw Data section bypasses the coalescer"
    assert "fetchRawOnce(alertId)" in component, "Fields section bypasses the coalescer"
    assert "fetchRawOnce(_current.id)" in component, "the tab-click loader bypasses the coalescer"


def test_the_case_rule_guide_shares_the_same_request(cases_js):
    fn = cases_js[cases_js.index("async function loadRuleGuideInto"):]
    fn = fn[:fn.index("\n}")]
    assert "window.ionAlertDetailFetchRaw" in fn, "the rule guide fetches /raw on its own again"


def test_the_coalescer_is_exported_for_the_page_to_use(component):
    assert "window.ionAlertDetailFetchRaw = fetchRawOnce" in component


def test_a_failed_fetch_is_retryable(component):
    """Caching a rejected promise would make one transient error permanent for
    that alert until the page is reloaded."""
    fn = component[component.index("function fetchRawOnce("):]
    fn = fn[:fn.index("\n  window.ionAlertDetailFetchRaw")]
    assert "delete _rawInflight[alertId]" in fn


def test_the_cache_is_keyed_per_alert(component):
    """A single shared promise would serve the previous alert's document after
    switching rows in the rail."""
    fn = component[component.index("function fetchRawOnce("):]
    fn = fn[:fn.index("\n  window.ionAlertDetailFetchRaw")]
    assert "_rawInflight[alertId]" in fn
    assert "_current.id === alertId" in fn


# ── Host / User / Source / Timestamp fill in ─────────────────────────────


def test_the_component_hydrates_a_thin_alert(component):
    assert "function _hydrateFromRaw(" in component
    assert "_hydrateFromRaw(alert);" in component, "mount never calls it"


def test_hydration_costs_no_extra_request(component):
    fn = component[component.index("function _hydrateFromRaw("):]
    fn = fn[:fn.index("\n  function mount(")]
    assert "fetchRawOnce(alert.id)" in fn, "hydration issues its own fetch"


@pytest.mark.parametrize("path", [
    "host.name", "host.hostname", "agent.name", "winlog.computer_name",
    "user.name", "winlog.event_data.SubjectUserName", "winlog.event_data.TargetUserName",
    "@timestamp", "event.dataset", "message",
])
def test_ecs_fallbacks_are_covered(path, component):
    """Windows alerts frequently carry the user only in event_data, and the
    host only as agent.name — a single canonical path would leave those blank."""
    assert path in component


def test_flattened_and_nested_documents_both_work(component):
    """Some pipelines emit `host.name` as a literal key, others nest it."""
    fn = component[component.index("function _ecs("):]
    fn = fn[:fn.index("\n  function _firstOf(")]
    assert "src[dotted] !== undefined" in fn
    assert "dotted.split('.')" in fn


def test_hydration_only_fills_genuine_blanks(component):
    """/alerts already supplies these. Overwriting them would make the two pages
    disagree about the same alert."""
    fn = component[component.index("function _setMeta("):]
    fn = fn[:fn.index("\n  function _hydrateFromRaw(")]
    assert "=== '-'" in fn
    hy = component[component.index("function _hydrateFromRaw("):]
    assert "if (host && !alert.host)" in hy


def test_meta_cells_are_addressable(component):
    for el_id in ("iad-meta-host", "iad-meta-user", "iad-meta-source", "iad-meta-timestamp"):
        assert el_id in component, f"{el_id} missing — hydration has nothing to patch"


def test_missing_timestamp_does_not_render_invalid_date(component):
    """`new Date(undefined).toLocaleString()` renders "Invalid Date", which is
    what a case alert produced before this."""
    assert "alert.timestamp ? new Date(alert.timestamp).toLocaleString() : '-'" in component


def test_hydration_failure_is_silent(component):
    """No raw document is the normal case when Elasticsearch is down — the grid
    should keep its dashes, not throw."""
    fn = component[component.index("function _hydrateFromRaw("):]
    fn = fn[:fn.index("\n  function mount(")]
    assert ".catch(" in fn


# ── healthcheck ──────────────────────────────────────────────────────────


def test_compose_healthcheck_allows_for_a_real_boot():
    compose = COMPOSE.read_text(encoding="utf-8")
    block = compose[compose.index("# Health check — used by seeder"):]
    block = block[:block.index("# Resource limits")]
    assert "start_period: 90s" in block
    assert "timeout: 10s" in block


def test_image_healthcheck_matches():
    """compose overrides this, but `docker run` of the image does not — a 10s
    start period makes the image look broken for its first half-minute."""
    df = DOCKERFILE.read_text(encoding="utf-8")
    line = next(ln for ln in df.splitlines() if ln.startswith("HEALTHCHECK"))
    assert "--start-period=90s" in line
    assert "--start-period=10s" not in line
