"""The /alerts triage queue (v0.81.0).

Covers the three things that would fail silently: the module reaching for a host
global it was not given, the queue dropping a DOM hook the page's existing
bulk-selection code still queries by, and the batch triage endpoint summarising
observables from free-form JSON.
"""
import re
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
JS = ROOT / "src" / "ion" / "web" / "static" / "js" / "alerts-queue.js"
CSS = ROOT / "src" / "ion" / "web" / "static" / "css" / "alerts-queue.css"
ALERTS = ROOT / "src" / "ion" / "web" / "templates" / "alerts.html"
BASE = ROOT / "src" / "ion" / "web" / "templates" / "base.html"


def _strip_comments(src: str) -> str:
    """Source-reading assertions match this file's own prose otherwise."""
    src = re.sub(r"/\*[\s\S]*?\*/", " ", src)
    return re.sub(r"^\s*//.*$", "", src, flags=re.M)


# ── the module must not reach for host globals ──────────────────────────────

HOST_GLOBALS = [
    "allAlerts", "filteredAlerts", "triageCache", "selectedAlertIds",
    "entityFilter", "arkimeEnabled", "currentUserData", "queueView",
    "showAlertDetail", "escapeHtml", "renderSystemBadge", "applyFilters",
]


@pytest.mark.parametrize("name", HOST_GLOBALS)
def test_queue_module_does_not_read_host_page_globals(name):
    """alert-detail.js reached for fourteen of alerts.html's top-level `let`s.

    They were undefined on /cases and every section that touched one hung on a
    spinner for three releases. Everything this module needs arrives via mount().
    """
    body = _strip_comments(JS.read_text(encoding="utf-8"))
    hits = [
        m for m in re.finditer(rf"(?<![\w.$]){re.escape(name)}(?![\w$])", body)
        # `host.systemBadge` etc. are injected, not ambient
        if not body[max(0, m.start() - 5):m.start()].endswith("host.")
    ]
    assert not hits, f"alerts-queue.js reads the host global `{name}` {len(hits)}x"


def test_queue_module_declares_its_dependencies_in_mount():
    src = JS.read_text(encoding="utf-8")
    for key in ("getAlerts", "getTriage", "selection", "actions", "table"):
        assert f"host.{key}" in src or f"{key}:" in src, f"mount() never uses {key}"


# ── DOM hooks the host page still queries by ────────────────────────────────

def test_queue_keeps_the_hooks_the_bulk_selection_code_uses():
    """updateBulkActionsUI() dereferences #header-select-all without a null check.

    Replacing the <thead> without re-emitting it made every selection change
    throw. Same for the row/checkbox classes the page's own handlers query.
    """
    js = JS.read_text(encoding="utf-8")
    for hook in ('id="header-select-all"', "alert-checkbox", "alert-row",
                 "data-alert-id", "'selected'"):
        assert hook in js, f"queue no longer emits the host hook {hook}"


def test_page_still_dereferences_those_hooks():
    """If the page stops using them, the guarantee above can be relaxed."""
    page = ALERTS.read_text(encoding="utf-8")
    assert "getElementById('header-select-all')" in page
    assert ".alert-checkbox" in page


# ── one cursor, not two ─────────────────────────────────────────────────────

def test_page_no_longer_runs_a_second_row_cursor():
    """selectedRowIndex + navigateAlerts bound j/k/Enter as well as the module,
    so one keypress moved two cursors that did not know about each other."""
    page = _strip_comments(ALERTS.read_text(encoding="utf-8"))
    for dead in ("selectedRowIndex", "navigateAlerts(", "updateSelectedRow("):
        assert dead not in page, f"the superseded row cursor is back: {dead}"


def test_module_stands_down_while_a_modal_is_open():
    page = ALERTS.read_text(encoding="utf-8")
    assert "isBlocked" in page, "mount() must pass isBlocked so modals own the keyboard"
    assert "isBlocked" in JS.read_text(encoding="utf-8")


# ── CSS tokens must exist ───────────────────────────────────────────────────

def test_queue_css_only_uses_tokens_that_exist():
    """var() falls back silently. `--ion-cyan` does not exist (it is
    `--color-ion-cyan`), so the colours looked right while ignoring the theme."""
    css_dir = ROOT / "src" / "ion" / "web" / "static" / "css"
    defined = set()
    for f in css_dir.glob("*.css"):
        defined |= set(re.findall(r"(--[\w-]+)\s*:", f.read_text(encoding="utf-8", errors="replace")))
    # some custom properties are set at runtime rather than declared in a
    # stylesheet — the sticky-header offset is measured, not hardcoded
    js_dir = ROOT / "src" / "ion" / "web" / "static" / "js"
    for f in list(js_dir.glob("*.js")) + [ALERTS]:
        if "min" in f.name:
            continue
        defined |= set(re.findall(r"setProperty\(\s*['\"](--[\w-]+)", f.read_text(encoding="utf-8", errors="replace")))
    used = set(re.findall(r"var\((--[\w-]+)", CSS.read_text(encoding="utf-8")))
    missing = sorted(used - defined)
    assert not missing, f"alerts-queue.css uses undefined tokens: {missing}"


def test_severity_low_is_not_given_an_accent_colour():
    """--sev-low is grey on purpose; low severity must not read as an accent."""
    css = CSS.read_text(encoding="utf-8")
    low = [ln for ln in css.splitlines() if "sv-low" in ln or "sev-low" in ln]
    assert low, "no low-severity rules found"
    for ln in low:
        assert "--color-ion-" not in ln, f"low severity uses an accent token: {ln.strip()}"


def test_queue_css_is_page_scoped_not_global():
    """base.html loads nine stylesheets on every page whether used or not."""
    assert "{% block head_css %}" in BASE.read_text(encoding="utf-8")
    assert "alerts-queue.css" in ALERTS.read_text(encoding="utf-8")
    assert "alerts-queue.css" not in BASE.read_text(encoding="utf-8")


# ── no inline styles ────────────────────────────────────────────────────────

@pytest.mark.parametrize("path", [JS, CSS])
def test_queue_assets_carry_no_inline_style_attribute(path):
    """Percentage widths are property writes; a style attribute would be refused
    by style-src-attr 'none' and the bar would draw at zero width."""
    src = path.read_text(encoding="utf-8")
    bad = re.findall(r"""(?<![-\w])style\s*=\s*["'][^"']*["']""", src)
    assert not bad, f"{path.name} emits inline style attributes: {bad[:3]}"


# ── batch triage summarises observables safely ──────────────────────────────

def _worst():
    api = (ROOT / "src" / "ion" / "web" / "api.py").read_text(encoding="utf-8")
    i = api.index("_THREAT_ORDER = [")
    j = api.index('@router.post("/elasticsearch/alerts-triage/batch")')
    ns: dict = {}
    exec(api[i:j], ns)  # noqa: S102 - executing our own source, not user input
    return ns["_worst_observable_threat"]


@pytest.mark.parametrize("observables,expected", [
    ([], "unknown"),
    ([{"threat_level": "benign"}, {"threat_level": "high"}], "high"),
    ([{"threat_level": "critical"}, {"threat_level": "low"}], "critical"),
    ([{"value": "1.2.3.4"}], "unknown"),
    (["a bare string", {"threat_level": "medium"}], "medium"),
    ([{"threat_level": "NONSENSE"}], "unknown"),
    ([{"threat_level": None}], "unknown"),
    ([{"threat_level": "HIGH"}], "high"),
])
def test_worst_observable_threat(observables, expected):
    """AlertTriage.observables is free-form JSON from several producers, so a row
    may be a bare string or missing the key. A malformed row must not decide the
    answer and must not raise on a list endpoint serving up to 500 alerts."""
    assert _worst()(observables) == expected


def _batch_handler(api: str) -> str:
    """The batch-triage handler, bounded by the NEXT route rather than a fixed
    character count — a window silently stops covering the function it is meant
    to assert on the moment the body grows."""
    start = api.index('@router.post("/elasticsearch/alerts-triage/batch")')
    nxt = api.find("@router.", start + 10)
    return api[start:nxt if nxt > 0 else len(api)]


def test_batch_triage_eager_loads_case_and_assignee():
    """Both are read per row. Lazy-loading issues one SELECT per alert on an
    endpoint called with up to 500 ids — the shape that was half of production
    response time at v0.79.4."""
    api = (ROOT / "src" / "ion" / "web" / "api.py").read_text(encoding="utf-8")
    body = _batch_handler(api)
    assert "joinedload(AlertTriage.case)" in body
    assert "joinedload(AlertTriage.assigned_to)" in body


def test_batch_triage_returns_the_fields_the_queue_columns_need():
    api = (ROOT / "src" / "ion" / "web" / "api.py").read_text(encoding="utf-8")
    body = _batch_handler(api)
    for field in ('"assigned_to"', '"suggested_verdict"', '"observable_count"',
                  '"observable_threat"'):
        assert field in body, f"batch triage no longer returns {field}"


def test_batch_triage_does_not_ship_whole_observable_lists():
    """500 alerts x their full observable arrays is a lot of payload for a count
    and a colour; the detail panel already fetches the full set."""
    api = (ROOT / "src" / "ion" / "web" / "api.py").read_text(encoding="utf-8")
    body = _batch_handler(api)
    assert '"observables": t.observables' not in body


# ── views describe what the data can answer ─────────────────────────────────

def test_saved_views_are_defined_and_include_the_unblocked_ones():
    page = ALERTS.read_text(encoding="utf-8")
    block = page[page.index("const AQ_VIEWS = ["):]
    block = block[:block.index("];") + 2]
    for key in ("active", "critical", "ageing", "uncased", "mine",
                "unassigned", "disagree", "autocase", "all"):
        assert f"k: '{key}'" in block, f"view `{key}` missing"


def test_a_view_narrows_the_aggregate_source_too():
    """An aggregate that ignores the active filter looks like an answer to the
    question you just asked."""
    page = _strip_comments(ALERTS.read_text(encoding="utf-8"))
    assert "matchesNonStatus(a) && matchesView(a)" in page


def test_filter_chips_cover_every_narrowing_not_just_the_entity():
    """#active-filter-banner only ever described the entity filter, so a
    severity + host narrowing showed one of the two."""
    page = ALERTS.read_text(encoding="utf-8")
    block = page[page.index("function renderFilterChips()"):]
    block = block[:block.index("\nfunction _clearChip")]
    for kind in ("'sev'", "'status'", "'system'", "'entity'", "'search'"):
        assert kind in block, f"chips do not cover {kind}"


# ── threat level comes from the registry, not the snapshot ──────────────────

def test_threat_level_is_looked_up_when_the_snapshot_does_not_carry_one():
    """Real AlertTriage.observables rows are `{"type","value"}` with NO
    threat_level — enrichment lives on the Observable registry. Reading only the
    snapshot returns "unknown" for every alert, i.e. a column that never changes.
    """
    worst = _worst()
    snapshot = [{"type": "ipv4", "value": "198.235.24.20"}]
    assert worst(snapshot) == "unknown", "no lookup map means no verdict"
    levels = {"198.235.24.20": "high"}
    assert worst(snapshot, levels) == "high"


def test_lookup_is_case_and_whitespace_insensitive():
    worst = _worst()
    obs = [{"type": "hostname", "value": "  ABACWKS042 "}]
    assert worst(obs, {"abacwks042": "critical"}) == "critical"


def test_snapshot_threat_level_wins_over_the_registry():
    """If a producer did record a level, it is closer to the alert than the
    registry's rollup for that value."""
    worst = _worst()
    obs = [{"value": "1.2.3.4", "threat_level": "critical"}]
    assert worst(obs, {"1.2.3.4": "benign"}) == "critical"


def test_registry_lookup_is_one_query_per_batch_not_one_per_alert():
    api = (ROOT / "src" / "ion" / "web" / "api.py").read_text(encoding="utf-8")
    fn = api[api.index("def _observable_threat_levels("):]
    fn = fn[:fn.index("\n@router")]
    assert fn.count(".all()") == 1, "the registry lookup must run once per batch"
    assert "normalized_value.in_(" in fn, "must be a single IN query"
    body = _batch_handler(api)
    assert body.count("_observable_threat_levels(") == 1
