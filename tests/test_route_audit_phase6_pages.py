"""Route audit phase 6 — page-level cheap wins.

- `/briefings` (static onboarding decks) sat one keystroke from `/briefing` (a
  live SOC data product). Renamed to `/about`.
- `/investigate` and `/investigations` differed by ONE character while being
  genuinely different pages — operate the queue vs mine the corpus. Renamed to
  `/investigation-queue` / `/investigation-memory`, matching the nav labels that
  already read that way.
- The Operations "Tools" nav item pointed at `/translator` (a 277-line
  single-purpose page) while the real 1076-line toolbox at `/tools` was only a
  second-level tab.
- `/wallboard` is a distinct, tested feature with its own service — and had zero
  inbound links anywhere in the app.
- `/daily-work` shipped a client-side "Shift handover" card covering one user's
  timeline, duplicating (worse) the server-side `/shift-handover` report.
- `gitlab.html` had a config modal writing the same `.ion/config.json` as
  `/settings#gitlab` — and handling the raw PAT, which `/settings` masks.

Renames keep 302 redirects so bookmarks survive (precedent: `/threat-landscape`,
`/attack-stories`).
"""

from __future__ import annotations

from pathlib import Path

import pytest

from ion.web.server import app

TEMPLATES = Path("src/ion/web/templates")


@pytest.fixture(scope="module")
def paths():
    return {r.path for r in app.routes}


@pytest.fixture(scope="module")
def base_html():
    return (TEMPLATES / "base.html").read_text(encoding="utf-8")


# ── renames + redirects ──────────────────────────────────────────────────


@pytest.mark.parametrize("new", ["/about", "/investigation-queue", "/investigation-memory"])
def test_renamed_pages_exist(paths, new):
    assert new in paths


@pytest.mark.parametrize("legacy", ["/briefings", "/investigate", "/investigations"])
def test_legacy_paths_still_served_as_redirects(paths, legacy):
    """Bookmarks must not 404 after a rename."""
    assert legacy in paths


def test_api_namespaces_untouched_by_page_renames(paths):
    """Only the PAGE routes were renamed — the API surface is unrelated."""
    assert "/api/investigate/jobs" in paths
    assert "/api/investigations" in paths


def test_briefing_and_about_are_distinct(paths):
    """The whole point of the rename: no more singular/plural collision."""
    assert "/briefing" in paths      # live SOC data product
    assert "/about" in paths          # static onboarding decks
    assert "/briefings" in paths      # legacy redirect only


# ── nav wiring ───────────────────────────────────────────────────────────


def test_tools_nav_points_at_the_toolbox(base_html):
    assert 'href="/tools"' in base_html
    tools_line = next(
        ln for ln in base_html.splitlines()
        if 'href="/tools"' in ln and "tw-drop-item" in ln
    )
    assert ">Tools<" in tools_line


def test_wallboard_is_reachable(base_html):
    assert 'href="/wallboard"' in base_html


def test_nav_uses_the_renamed_paths(base_html):
    assert 'href="/investigation-queue"' in base_html
    assert 'href="/investigation-memory"' in base_html
    assert 'href="/about"' in base_html
    # the old page paths must not be linked any more (redirects are for bookmarks)
    assert 'href="/investigate"' not in base_html
    assert 'href="/briefings"' not in base_html


# ── duplicated widgets removed ───────────────────────────────────────────


def test_daily_work_defers_to_the_real_handover():
    html = (TEMPLATES / "daily_work.html").read_text(encoding="utf-8")
    assert 'href="/shift-handover"' in html, "should link to the real report"
    assert "generateHandover" not in html, "client-side duplicate must be gone"
    assert "dw-handover" not in html, "orphaned ids/CSS left behind"


def test_gitlab_config_lives_only_on_settings():
    html = (TEMPLATES / "gitlab.html").read_text(encoding="utf-8")
    assert 'href="/settings#gitlab"' in html
    assert 'id="config-modal"' not in html
    for fn in ("showConfigModal", "closeConfigModal", "saveConfig", "disableGitLab"):
        assert f"function {fn}(" not in html, f"{fn} left dangling"
    # the raw-token inputs are gone with the modal
    assert 'id="gitlab-token"' not in html


def test_gitlab_issue_browser_survived():
    """Only the config surface was removed — the page's actual job stays."""
    html = (TEMPLATES / "gitlab.html").read_text(encoding="utf-8")
    assert "/api/gitlab/issues" in html
