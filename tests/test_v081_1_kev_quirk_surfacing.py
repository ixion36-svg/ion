"""KEV and System-Quirk advisories reach the analyst (v0.81.1).

Both were attached to the alerts API with nothing rendering them — quirks since
v0.57.0, KEV as Bob prompt ground truth since v0.79.1. The server did the work
and the client dropped it, so **Bob was told which CVEs are actively exploited
and the analyst reading the same alert was not**.

The asymmetry is the bug. These tests pin both halves: the annotation being
attached, and something actually reading it.
"""
import re
from pathlib import Path
from unittest.mock import MagicMock

import pytest

ROOT = Path(__file__).resolve().parents[1]
QUEUE_JS = ROOT / "src" / "ion" / "web" / "static" / "js" / "alerts-queue.js"
DETAIL_JS = ROOT / "src" / "ion" / "web" / "static" / "js" / "alert-detail.js"
ALERTS = ROOT / "src" / "ion" / "web" / "templates" / "alerts.html"
ES_API = ROOT / "src" / "ion" / "web" / "elasticsearch_api.py"


class _Entry:
    def __init__(self, cve, ransomware=False, name="Test RCE"):
        self.cve_id = cve
        self.known_ransomware = ransomware
        self.vulnerability_name = name
        self.date_added = None
        self.due_date = None


def _session(entries):
    s = MagicMock()
    s.query.return_value.filter.return_value.all.return_value = entries
    return s


# ── the annotation is attached ──────────────────────────────────────────────

def test_kev_annotation_attaches_only_to_alerts_carrying_a_listed_cve():
    from ion.services.kev_service import annotate_alerts
    alerts = [
        {"id": "1", "title": "Exploit for CVE-2024-21412"},
        {"id": "2", "title": "Nothing here"},
    ]
    annotate_alerts(_session([_Entry("CVE-2024-21412")]), alerts)
    assert [a["kev"][0]["cve_id"] for a in alerts if "kev" in a] == ["CVE-2024-21412"]
    assert "kev" not in alerts[1]


def test_a_cve_absent_from_the_catalogue_is_not_recorded_as_safe():
    """A snapshot cannot know about a CVE published after it was cut. Recording
    a miss would let "not in KEV" be read as evidence of safety — exactly
    backwards for a CVE published last week."""
    from ion.services.kev_service import annotate_alerts
    alerts = [{"id": "1", "title": "CVE-1999-0001 and CVE-2023-23397"}]
    annotate_alerts(_session([_Entry("CVE-2023-23397")]), alerts)
    assert [h["cve_id"] for h in alerts[0]["kev"]] == ["CVE-2023-23397"]
    assert "CVE-1999-0001" not in str(alerts[0]["kev"])


def test_ransomware_linkage_survives_to_the_client():
    """The one KEV fact that changes what an analyst does first."""
    from ion.services.kev_service import annotate_alerts
    alerts = [{"id": "1", "title": "CVE-2024-21412"}]
    annotate_alerts(_session([_Entry("CVE-2024-21412", ransomware=True)]), alerts)
    assert alerts[0]["kev"][0]["known_ransomware"] is True


def test_kev_annotation_is_case_insensitive():
    from ion.services.kev_service import annotate_alerts
    alerts = [{"id": "1", "message": "cve-2024-21412 in lowercase"}]
    annotate_alerts(_session([_Entry("CVE-2024-21412")]), alerts)
    assert "kev" in alerts[0]


def test_kev_annotation_is_additive_and_never_fatal():
    """It must not remove, reorder or filter an alert, and a lookup failure must
    not empty the alerts view."""
    from ion.services.kev_service import annotate_alerts
    alerts = [{"id": "1", "title": "CVE-2024-21412"}, {"id": "2"}, "not a dict"]
    out = annotate_alerts(_session([_Entry("CVE-2024-21412")]), alerts)
    assert out is alerts and len(out) == 3

    broken = MagicMock()
    broken.query.side_effect = RuntimeError("db down")
    survived = annotate_alerts(broken, [{"id": "x", "title": "CVE-2024-21412"}])
    assert len(survived) == 1 and "kev" not in survived[0]


def test_kev_lookup_is_one_query_per_page():
    src = (ROOT / "src" / "ion" / "services" / "kev_service.py").read_text(encoding="utf-8")
    fn = src[src.index("def annotate_alerts("):]
    fn = fn[:fn.index("\ndef ")]
    assert fn.count("lookup_many(") == 1, "must batch, not look up per alert"


def test_both_annotators_run_on_the_alerts_list():
    src = ES_API.read_text(encoding="utf-8")
    assert "de_quirk_service import annotate_alerts" in src
    assert "kev_service import annotate_alerts" in src


# ── something actually renders it ───────────────────────────────────────────

def _strip_comments(src: str) -> str:
    src = re.sub(r"/\*[\s\S]*?\*/", " ", src)
    return re.sub(r"^\s*//.*$", "", src, flags=re.M)


@pytest.mark.parametrize("key", ["kev", "quirks"])
def test_the_queue_reads_the_annotation(key):
    """The whole point. `grep quirks` over the client returned zero hits for
    twenty-four releases while the server attached it on every request."""
    body = _strip_comments(QUEUE_JS.read_text(encoding="utf-8"))
    assert re.search(rf"a\.{key}\b", body), f"the queue never reads alert.{key}"


@pytest.mark.parametrize("key", ["kev", "quirks"])
def test_the_detail_panel_reads_the_annotation(key):
    body = _strip_comments(DETAIL_JS.read_text(encoding="utf-8"))
    assert re.search(rf"alert\.{key}\b", body), f"the detail panel never reads alert.{key}"


def test_a_quirk_is_presented_as_advisory_not_as_severity():
    """A quirk explains an alert; it must never be read as how bad it is, and
    the no-suppression guarantee has to be visible to the person triaging."""
    detail = DETAIL_JS.read_text(encoding="utf-8")
    assert "Advisory only" in detail
    assert "never suppresses" in detail


def test_quirk_styling_does_not_use_a_severity_colour():
    for css in (ROOT / "src/ion/web/static/css/alerts-queue.css",
                ROOT / "src/ion/web/static/css/alert-detail.css"):
        text = css.read_text(encoding="utf-8")
        for block in re.findall(r"\.(?:aq-tag\.aq-quirk|iad-adv-quirk)\s*\{[^}]*\}", text):
            assert "--sev-critical" not in block and "--sev-high" not in block, \
                f"quirk styling borrows a severity colour: {block[:80]}"


def test_kev_and_quirk_are_findable_not_just_visible():
    """A badge you cannot filter to is only useful on the row you happen to be
    looking at."""
    page = ALERTS.read_text(encoding="utf-8")
    block = page[page.index("const AQ_VIEWS = ["):]
    block = block[:block.index("];") + 2]
    assert "k: 'kev'" in block
    assert "k: 'quirked'" in block
