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


# ── phase 7: page merges ─────────────────────────────────────────────────


@pytest.mark.parametrize("retired,target", [
    ("/engineering-analytics", "/analytics"),
    ("/ai-scorecard", "/alert-prompts"),
    ("/my-courses", "/courses"),
])
def test_retired_pages_redirect_not_404(paths, retired, target):
    """Merged-away pages keep a route so links and bookmarks survive."""
    assert retired in paths
    assert target in paths


def test_retired_templates_are_gone():
    for name in ("engineering_analytics.html", "ai_scorecard.html", "my_courses.html"):
        assert not (TEMPLATES / name).exists(), f"{name} should have been deleted"


def test_index_breakdown_ported_into_analytics():
    """The only section unique to /engineering-analytics moved rather than died."""
    html = (TEMPLATES / "analytics.html").read_text(encoding="utf-8")
    assert "index-table-container" in html
    assert "function renderIndexTable(" in html
    assert "renderIndexTable(data.indices" in html


def test_analytics_bar_widths_are_not_the_dead_migrated_class():
    """The v0.31.21 inline-style migration hashed `width:${pct}%` into a STATIC
    class, leaving a literal ${pct} in the CSS — an invalid rule browsers drop,
    so every bar on this page rendered at zero width."""
    html = (TEMPLATES / "analytics.html").read_text(encoding="utf-8")
    # no element should still carry the dead class
    assert 'class="risk-bar ${cls} _ion-s-95aea49e0e"' not in html
    assert "_ion-s-95aea49e0e\"></div>" not in html
    assert "function applyBarWidths(" in html
    assert html.count("data-pct=") >= 4


def test_ai_scorecard_kpis_folded_into_alert_prompts():
    html = (TEMPLATES / "alert_prompt_templates.html").read_text(encoding="utf-8")
    for tile in ("sc-kpi-templates", "sc-kpi-samples", "sc-kpi-agreement", "sc-kpi-tuning"):
        assert tile in html
    assert "function renderScorecardKpis" in html
    # the old page approximated `evaluated`; the KPI must use the real count
    assert "c.evaluated" in html


def test_scorecards_api_exposes_exact_evaluated_count():
    src = Path("src/ion/web/alert_prompt_api.py").read_text(encoding="utf-8")
    assert '"evaluated": b["evaluated"]' in src


def test_courses_page_has_scope_toggle():
    html = (TEMPLATES / "courses.html").read_text(encoding="utf-8")
    assert "cl-scope-all" in html and "cl-scope-mine" in html
    assert "'/api/my-courses'" in html, "toggle must still call the enrolment endpoint"


def test_my_courses_api_survived_the_page_merge(paths):
    assert "/api/my-courses" in paths


@pytest.mark.parametrize("tpl", ["bug_reports.html", "change_requests.html"])
def test_service_desk_pages_share_a_tab_strip(tpl):
    html = (TEMPLATES / tpl).read_text(encoding="utf-8")
    assert '_nav_tabs.html' in html
    assert '"/bug-reports"' in html


def test_cab_tab_is_permission_gated():
    """bug-reports is any-authenticated; change-requests is system:settings. The
    tab strip must not advertise CAB to users who cannot open it."""
    from jinja2 import Environment, FileSystemLoader

    src = (TEMPLATES / "bug_reports.html").read_text(encoding="utf-8")
    frag = src[src.index("{% set tabs = ["):
               src.index('{% include "_nav_tabs.html" %}') + len('{% include "_nav_tabs.html" %}')]
    env = Environment(loader=FileSystemLoader(str(TEMPLATES)))

    class _U:
        def __init__(self, ok): self._ok = ok
        def has_permission(self, _p): return self._ok

    assert "Change Requests" in env.from_string(frag).render(current_user=_U(True))
    assert "Change Requests" not in env.from_string(frag).render(current_user=_U(False))
    assert "Change Requests" not in env.from_string(frag).render(current_user=None)


def test_service_desk_routes_pass_current_user():
    """The gate above is inert unless the route actually supplies current_user."""
    for mod in ("bug_report_api.py", "change_request_api.py"):
        src = Path("src/ion/web") .joinpath(mod).read_text(encoding="utf-8")
        assert '"current_user": _user' in src, f"{mod} must pass current_user"


def test_analyst_efficiency_merged_into_executive_report(paths):
    assert "/analyst-efficiency" in paths          # redirect
    assert not (TEMPLATES / "analyst_efficiency.html").exists()
    assert "/api/analyst-efficiency/metrics" in paths   # API backs the Team tab
    html = (TEMPLATES / "executive_report.html").read_text(encoding="utf-8")
    assert "er-tab-team" in html and "function erLoadTeam" in html
    assert "Per-Analyst Breakdown" in html
    # the activity bars must not use the dead migrated height rule
    assert 'class="ae-activity-bar _ion-s-9ce2eb0cde"' not in html
    assert "b.style.height" in html


@pytest.mark.parametrize("tpl", ["detection_health.html", "de_metrics.html"])
def test_detection_pages_share_a_permission_aware_strip(tpl):
    html = (TEMPLATES / tpl).read_text(encoding="utf-8")
    assert '_nav_tabs.html' in html
    assert 'has_permission("de:read")' in html
    assert 'has_permission("security:read")' in html


def test_detection_strip_never_advertises_an_unauthorised_tab():
    from jinja2 import Environment, FileSystemLoader

    src = (TEMPLATES / "de_metrics.html").read_text(encoding="utf-8")
    end = '{% if tabs | length > 1 %}{% include "_nav_tabs.html" %}{% endif %}'
    frag = src[src.index("{% set tabs = [] %}"): src.index(end) + len(end)]
    env = Environment(loader=FileSystemLoader(str(TEMPLATES)))

    class _U:
        def __init__(self, perms): self._p = perms
        def has_permission(self, p): return p in self._p

    both = env.from_string(frag).render(current_user=_U({"de:read", "security:read"}),
                                        active_label="DE Metrics")
    assert "DE Metrics" in both and "Detection Health" in both

    de_only = env.from_string(frag).render(current_user=_U({"de:read"}),
                                           active_label="DE Metrics")
    assert "Detection Health" not in de_only, "must not advertise a page the user cannot open"

    anon = env.from_string(frag).render(current_user=None, active_label="DE Metrics")
    assert "Detection Health" not in anon and "DE Metrics" not in anon


def test_detection_routes_pass_current_user():
    src = Path("src/ion/web/server.py").read_text(encoding="utf-8")
    assert src.count('context={"current_user": user}') >= 2
