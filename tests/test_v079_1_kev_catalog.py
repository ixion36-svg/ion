"""v0.79.1 — the CISA KEV catalog, shipped as a snapshot.

ION deploys air-gapped, so there is no feed to poll: the catalog travels inside
the image, is seeded on startup, and can be topped up by an operator uploading
a file they fetched themselves. `scripts/refresh_kev_snapshot.py` pulls a newer
catalog into the bundle at RELEASE time — that script is the only thing in the
repo that talks to cisa.gov, and it is a developer tool, not runtime code.

The tests that matter most are the ones about how a MISS is worded.

Bob is handed KEV membership as deterministic ground truth, for the same reason
the PowerShell decode is: asked "is CVE-X known-exploited", a model answers from
half-remembered CVE numbering, confidently, and wrongly in both directions. But
the dangerous failure is not a wrong "yes" — it is a bare "no". Given "not in
KEV", a model reasons *not in KEV -> not urgent -> probably benign*, which is
exactly backwards for a CVE published after the snapshot was taken. So every
miss must carry the catalog version and say it is absence-from-a-snapshot, and
must never assert the CVE is unexploited or low risk.
"""

from __future__ import annotations

import json
from datetime import date
from pathlib import Path

import pytest

from ion.services import kev_service

BUNDLE = Path("src/ion/data/kev_catalog.json")


# ── the shipped snapshot ─────────────────────────────────────────────────


def test_catalog_ships_with_the_image():
    """Air-gapped sites have no way to fetch this — if it is not in the repo it
    is not in the image, and KEV is silently empty everywhere."""
    assert BUNDLE.exists(), "the bundled KEV snapshot is missing"


def test_bundle_parses_and_is_a_real_catalog():
    version, released, rows = kev_service.load_bundle()
    assert version, "no catalogVersion"
    assert len(rows) > 500, f"only {len(rows)} entries — is this a truncated download?"
    assert all(r["cve_id"].startswith("CVE-") for r in rows)


def test_bundle_is_minified():
    """The published feed is ~40% whitespace and this ships in the image."""
    raw = BUNDLE.read_text(encoding="utf-8")
    assert "\n  " not in raw[:2000], "snapshot looks pretty-printed"


def test_refresh_script_never_runs_at_runtime():
    """The one place that reaches out to CISA must be a dev script, not
    importable application code.

    Asserting on the string "cisa.gov" is the wrong test — KB articles link to
    the catalog and this module's own docstring names it. The contract is that
    no application module makes a NETWORK CALL for it.
    """
    script = Path("scripts/refresh_kev_snapshot.py")
    assert script.exists()
    assert "urllib.request" in script.read_text(encoding="utf-8")

    # ion/data holds KNOWLEDGE-BASE ARTICLE TEXT, not executable app code — the
    # articles legitimately show a curl of the KEV feed and requests.get()
    # examples, in different articles, as teaching material.
    fetchers = ("urlopen(", "requests.get(", "httpx.get(", "httpx.AsyncClient(")
    offenders = []
    for f in Path("src/ion").rglob("*.py"):
        if "data" in f.parts:
            continue
        body = f.read_text(encoding="utf-8", errors="ignore")
        if "cisa.gov" in body and any(fn in body for fn in fetchers):
            offenders.append(str(f))
    assert not offenders, f"application code fetches from cisa.gov: {offenders}"


# ── parsing ──────────────────────────────────────────────────────────────


def _doc(**over):
    base = {
        "catalogVersion": "2026.01.01",
        "dateReleased": "2026-01-01T00:00:00Z",
        "vulnerabilities": [{
            "cveID": "CVE-2026-1111", "vendorProject": "Acme", "product": "Widget",
            "vulnerabilityName": "Acme Widget RCE", "dateAdded": "2026-01-01",
            "dueDate": "2026-01-21", "knownRansomwareCampaignUse": "Known",
            "shortDescription": "boom", "requiredAction": "patch",
        }],
    }
    base.update(over)
    return base


def test_parse_rejects_a_document_with_no_version():
    with pytest.raises(kev_service.KevImportError):
        kev_service.parse_catalog(_doc(catalogVersion=""))


def test_parse_rejects_an_empty_or_wrong_shaped_document():
    for bad in ({}, {"vulnerabilities": []}, {"vulnerabilities": "nope"}, []):
        with pytest.raises(kev_service.KevImportError):
            kev_service.parse_catalog(bad)


def test_parse_drops_entries_with_no_cve_id():
    """A row without a CVE cannot be looked up or deduplicated."""
    doc = _doc(vulnerabilities=[{"cveID": "", "product": "x"},
                                {"cveID": "CVE-2026-2222", "product": "y"}])
    _v, _r, rows = kev_service.parse_catalog(doc)
    assert [r["cve_id"] for r in rows] == ["CVE-2026-2222"]


def test_unknown_ransomware_is_not_recorded_as_false():
    """CISA publishes "Known"/"Unknown". "Unknown" means NOT ESTABLISHED, not
    "no" — collapsing it to a bare False asserts something the catalog does
    not, so the raw value is kept alongside the boolean."""
    _v, _r, rows = kev_service.parse_catalog(
        _doc(vulnerabilities=[{"cveID": "CVE-2026-3333",
                               "knownRansomwareCampaignUse": "Unknown"}]))
    assert rows[0]["known_ransomware"] is False
    assert rows[0]["known_ransomware_raw"] == "Unknown"


def test_dates_parse_and_malformed_dates_do_not_raise():
    _v, _r, rows = kev_service.parse_catalog(
        _doc(vulnerabilities=[{"cveID": "CVE-2026-4444", "dateAdded": "2026-02-03",
                               "dueDate": "not-a-date"}]))
    assert rows[0]["date_added"] == date(2026, 2, 3)
    assert rows[0]["due_date"] is None


# ── CVE extraction ───────────────────────────────────────────────────────


@pytest.mark.parametrize("text,expected", [
    ("exploit for CVE-2026-8037 seen", ["CVE-2026-8037"]),
    ("cve-2026-8037 lowercase", ["CVE-2026-8037"]),
    ("CVE-2026-8037 and CVE-2026-8037 again", ["CVE-2026-8037"]),
    ("CVE-2021-44228 plus CVE-2026-1234567", ["CVE-2021-44228", "CVE-2026-1234567"]),
    ("no cves here", []),
    ("CVE-20-1 is malformed", []),
])
def test_extract_cve_ids(text, expected):
    assert kev_service.extract_cve_ids(text) == expected


def test_extract_is_bounded():
    blob = " ".join(f"CVE-2026-{i:04d}" for i in range(1, 60))
    assert len(kev_service.extract_cve_ids(blob, limit=12)) == 12


# ── the prompt block: how a MISS is worded ───────────────────────────────


class _FakeQuery:
    def __init__(self, rows): self._rows = rows
    def filter(self, *a, **k): return self
    def all(self): return self._rows
    def scalar(self): return self._rows[0] if self._rows else None
    def distinct(self): return self
    def one_or_none(self): return self._rows[0] if self._rows else None


class _FakeSession:
    """Enough session to drive kev_prompt_block without a database."""
    def __init__(self, entries=(), version="2026.08.07", count=1662, age=3):
        self._entries = list(entries)
        self._version, self._count, self._age = version, count, age
    def query(self, *args, **kwargs): return _FakeQuery(self._entries)


@pytest.fixture
def patched_status(monkeypatch):
    def _apply(entries, version="2026.08.07", age=3, loaded=True):
        monkeypatch.setattr(kev_service, "status", lambda s: {
            "loaded": loaded, "count": 1662, "catalog_version": version,
            "age_days": age, "sources": ["bundled"],
        })
        monkeypatch.setattr(kev_service, "lookup_many",
                            lambda s, cves: {e.cve_id: e for e in entries})
    return _apply


class _Entry:
    def __init__(self, cve, ransom=False):
        self.cve_id = cve
        self.vendor_project, self.product = "Progress", "LoadMaster"
        self.date_added, self.due_date = date(2026, 8, 7), date(2026, 8, 10)
        self.known_ransomware = ransom


def test_a_miss_names_the_catalog_and_refuses_to_imply_safety(patched_status):
    """THE test. A bare "not in KEV" leads a model to 'not urgent -> benign',
    which is exactly wrong for a CVE newer than the snapshot."""
    patched_status(entries=[])
    lines = kev_service.kev_prompt_block(_FakeSession(), "seen CVE-2026-9999 in logs")
    text = "\n".join(lines)

    assert "CVE-2026-9999" in text
    assert "NOT PRESENT in KEV catalog 2026.08.07" in text
    assert "post-date this snapshot" in text
    # It must not tell the model the CVE is fine.
    for forbidden in ("not exploited", "unexploited and", "is safe", "low risk CVE"):
        assert forbidden not in text.lower().replace("is not a statement that the cve is unexploited or low risk", "")


def test_the_block_states_it_is_ground_truth_and_bounded_by_a_snapshot(patched_status):
    patched_status(entries=[])
    text = "\n".join(kev_service.kev_prompt_block(_FakeSession(), "CVE-2026-9999"))
    assert "DO NOT infer" in text
    assert "2026.08.07" in text
    assert "3 days old" in text


def test_a_hit_is_stated_as_listed_with_its_evidence(patched_status):
    patched_status(entries=[_Entry("CVE-2026-8037")])
    text = "\n".join(kev_service.kev_prompt_block(_FakeSession(), "CVE-2026-8037 exploited"))
    assert "LISTED IN CISA KEV" in text
    assert "2026-08-07" in text
    assert "LoadMaster" in text


def test_ransomware_use_is_surfaced(patched_status):
    patched_status(entries=[_Entry("CVE-2026-8037", ransom=True)])
    text = "\n".join(kev_service.kev_prompt_block(_FakeSession(), "CVE-2026-8037"))
    assert "known ransomware campaign use" in text


def test_kev_is_advisory_not_a_verdict(patched_status):
    """Same posture as System Quirks: it annotates, it does not decide. A model
    told KEV membership sets severity would stop analysing."""
    patched_status(entries=[_Entry("CVE-2026-8037")])
    text = "\n".join(kev_service.kev_prompt_block(_FakeSession(), "CVE-2026-8037"))
    assert "advisory input" in text
    assert "not an automatic verdict" in text


def test_no_cves_means_no_block(patched_status):
    patched_status(entries=[])
    assert kev_service.kev_prompt_block(_FakeSession(), "nothing to see") == []


def test_empty_catalog_means_no_block(patched_status):
    """Better to say nothing than to tell the model 'not in KEV' from a catalog
    that was never loaded."""
    patched_status(entries=[], loaded=False)
    assert kev_service.kev_prompt_block(_FakeSession(), "CVE-2026-9999") == []


def test_block_never_raises(monkeypatch):
    """Enrichment must never break triage."""
    def boom(*a, **k):
        raise RuntimeError("db gone")
    monkeypatch.setattr(kev_service, "status", boom)
    assert kev_service.kev_prompt_block(_FakeSession(), "CVE-2026-9999") == []


# ── wiring ───────────────────────────────────────────────────────────────


def test_both_prompt_paths_inject_kev():
    src = Path("src/ion/services/investigation_service.py").read_text(encoding="utf-8")
    assert src.count("_kev_lines(") >= 3, "KEV is missing from the alert or cluster prompt"
    assert "def _kev_lines(" in src


def test_import_endpoint_is_admin_gated_and_audited():
    api = Path("src/ion/web/kev_api.py").read_text(encoding="utf-8")
    imp = api[api.index("def kev_import"):]
    assert 'require_permission("system:settings")' in api
    assert 'action="kev_catalog_import"' in imp
    assert "_MAX_IMPORT_BYTES" in imp


def test_there_is_no_runtime_refresh_endpoint():
    """A 'fetch from CISA' button would be dead weight in an air-gapped site
    and a surprise egress call in a connected one."""
    api = Path("src/ion/web/kev_api.py").read_text(encoding="utf-8")
    assert "urlopen" not in api and "requests.get" not in api and "httpx" not in api


def test_seed_is_wired_with_its_own_advisory_lock():
    server = Path("src/ion/web/server.py").read_text(encoding="utf-8")
    db = Path("src/ion/storage/database.py").read_text(encoding="utf-8")
    assert "LOCK_SEED_KEV_CATALOG" in db and "LOCK_SEED_KEV_CATALOG" in server
    assert "seed_kev_catalog" in server


def test_seed_will_not_downgrade_an_operator_import():
    """If a site imported a newer catalog, redeploying an older image must not
    drag them backwards."""
    src = Path("src/ion/services/kev_service.py").read_text(encoding="utf-8")
    fn = src[src.index("def seed_from_bundle"):]
    fn = fn[:fn.index("\ndef ")]
    assert "current >= version" in fn


def test_reimport_removes_withdrawn_cves():
    """CISA does remove entries. A stale row keeps ION asserting
    'known exploited' about something the catalog no longer does."""
    src = Path("src/ion/services/kev_service.py").read_text(encoding="utf-8")
    fn = src[src.index("def _apply("):]
    fn = fn[:fn.index("\ndef ")]
    assert "session.delete(entry)" in fn
