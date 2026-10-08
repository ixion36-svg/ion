"""Guards for two page defects the review work shipped and rendering caught.

Both were in ``response_approvals.html``, the one template added from
scratch during stage 3. Both were invisible to every test written for it,
because those tests asserted the *route* existed and the *template*
existed — never that the page could reach the route.

**A script tag with no CSP nonce.** ION serves a strict
``script-src 'self' 'nonce-…'``. A ``<script>`` without the nonce is
blocked outright, so the page's entire JavaScript never ran: the panel sat
on "Loading approvals..." for ever with one console error and a clean
server log. Every other ION template writes
``<script nonce="{{ csp_nonce }}">``; this one did not, and nothing said so.

**A fetch path missing the router's mount prefix.** The page used
``/response/actions/inbox``. The router declares ``prefix="/response"`` and
``server.py`` mounts it with ``include_router(response_router,
prefix="/api")``, so the served path is ``/api/response/actions/inbox``. The
test for that endpoint read the *source* of ``response_api.py`` and found
``@router.get("/actions/inbox")`` — which is true, and says nothing about
what URL a browser should ask for.

The first test below is a one-liner that would have caught the first defect.
The second compares every absolute fetch path in every template against the
app's real route table, which would have caught the second. Both are
structural: they hold for templates nobody has written yet.
"""

from __future__ import annotations

import re
import sys
from pathlib import Path

import pytest

_SRC = Path(__file__).resolve().parent.parent / "src"
if str(_SRC) not in sys.path:
    sys.path.insert(0, str(_SRC))

_TEMPLATES = _SRC / "ion" / "web" / "templates"


def _template_files():
    return sorted(_TEMPLATES.rglob("*.html"))


# ── Every inline script carries the nonce ────────────────────────────────


class TestCspNonce:
    def test_the_template_directory_is_where_this_thinks(self):
        """If the glob finds nothing, every test here passes vacuously."""
        assert len(_template_files()) > 30

    def test_no_template_has_a_script_tag_without_the_nonce(self):
        """A bare <script> is silently dead under ION's CSP."""
        offenders = []
        for path in _template_files():
            text = path.read_text(encoding="utf-8")
            for match in re.finditer(r"<script(?![^>]*\bsrc\s*=)([^>]*)>", text):
                attrs = match.group(1)
                if "csp_nonce" not in attrs:
                    line = text[: match.start()].count("\n") + 1
                    offenders.append(f"{path.name}:{line}")
        assert not offenders, (
            "inline <script> without nonce=\"{{ csp_nonce }}\" — ION's CSP "
            f"blocks these and the page's JS never runs: {offenders}"
        )

    def test_external_scripts_are_not_required_to_carry_one(self):
        """A <script src=...> is covered by 'self', so the rule above
        deliberately skips them. Asserted so the exemption is intentional
        rather than an accident of the regex."""
        base = (_TEMPLATES / "base.html").read_text(encoding="utf-8")
        assert re.search(r"<script[^>]*\bsrc\s*=", base)


# ── Every fetch path is a route the app serves ───────────────────────────


_IGNORED_PREFIXES = (
    "/static/",
)


def _template_fetch_paths() -> dict[str, list[str]]:
    """``{template: [absolute literal fetch paths]}``.

    Only literal, absolute, single-quoted paths. A path built by
    concatenation (``'/api/cases/' + id``) contributes the prefix, which is
    what matters — the mount is either right or wrong for all of them.
    """
    found: dict[str, list[str]] = {}
    pattern = re.compile(r"""fetch\(\s*[`'"](/[A-Za-z0-9/_.-]*)""")
    for path in _template_files():
        hits = {
            m.group(1)
            for m in pattern.finditer(path.read_text(encoding="utf-8"))
            if not m.group(1).startswith(_IGNORED_PREFIXES)
        }
        if hits:
            found[path.name] = sorted(hits)
    return found


@pytest.fixture(scope="module")
def served_paths() -> set[str]:
    """Every path the app serves, with parameters normalised away."""
    from ion.web.server import app

    paths = set()
    for route in app.routes:
        template = getattr(route, "path", None)
        if not template:
            continue
        paths.add(template)
        # "/api/cases/{case_id}/pins" -> "/api/cases" so a prefix check on a
        # concatenated client path still matches.
        if "{" in template:
            paths.add(template.split("/{")[0])
    return paths


def _is_served(candidate: str, served: set[str]) -> bool:
    trimmed = candidate.rstrip("/") or "/"
    if trimmed in served or candidate in served:
        return True
    # A concatenated client path contributes a prefix ending in "/".
    return any(
        s == trimmed or s.startswith(trimmed + "/") or trimmed.startswith(s + "/")
        for s in served
    )


class TestFetchPaths:
    def test_some_fetch_paths_were_found(self):
        """Guards the regex, as above."""
        found = _template_fetch_paths()
        total = sum(len(v) for v in found.values())
        assert total > 50, f"only found {total} fetch paths; the regex is wrong"

    def test_every_template_fetch_path_is_served(self, served_paths):
        """The defect: /response/actions/inbox, when the router is mounted
        at /api and the served path is /api/response/actions/inbox."""
        offenders = []
        for template, paths in _template_fetch_paths().items():
            for candidate in paths:
                if not _is_served(candidate, served_paths):
                    offenders.append(f"{template} -> {candidate}")
        assert not offenders, (
            "these pages fetch paths the app does not serve, so the feature "
            f"is dead in the browser however well the route is tested: {offenders}"
        )

    def test_the_approval_inbox_uses_the_mounted_prefix(self):
        """The specific regression, named so it cannot come back quietly."""
        page = (_TEMPLATES / "response_approvals.html").read_text(encoding="utf-8")
        assert "const RAP_API = '/api/response'" in page
        assert "'/response'" not in page

    def test_the_check_would_reject_an_unmounted_path(self, served_paths):
        """Proves the check has teeth rather than matching everything."""
        assert not _is_served("/response/actions/inbox", served_paths)
        assert _is_served("/api/response/actions/inbox", served_paths)
