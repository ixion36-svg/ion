"""Tests for executive_report_service — the weekly report leadership reads.

This module was at 0% when the coverage ratchet first measured the tree. Nobody
reading this report can check it, which makes two failure classes expensive:

* a figure drawn from the wrong window or the wrong population, which an
  executive cannot tell from a correct one;
* the HTML. The report interpolates case titles, usernames and closure reasons
  straight into markup. Those strings came from Elasticsearch alert data, so a
  case title is attacker-influenced input, and this file is rendered to PDF and
  mailed outside the SOC. `_esc` is the only thing standing between the two, so
  it is tested as a security control, not a formatting helper.
"""

from __future__ import annotations

import sys
from datetime import datetime, timedelta

import pytest

from ion.models.alert_triage import AlertCase, AlertCaseStatus, AlertTriage
from ion.models.user import AuditLog, User
from ion.services.executive_report_service import (
    _alert_metrics,
    _case_metrics,
    _compute_trends,
    _esc,
    _fmt,
    _notable_incidents,
    _team_metrics,
    generate_executive_html,
    generate_executive_pdf,
    generate_executive_report,
)

# A fixed "now" well clear of any real clock, and a cutoff seven days back.
NOW = datetime(2026, 6, 15, 12, 0, 0)
CUTOFF = NOW - timedelta(days=7)
BEFORE = CUTOFF - timedelta(days=3)


class _Seq:
    n = 0

    @classmethod
    def next(cls):
        cls.n += 1
        return f"EXEC-{cls.n:05d}"


@pytest.fixture
def analyst(session):
    u = User(username="alice", email="alice@example.com", password_hash="x",
             is_active=True)
    session.add(u)
    session.flush()
    return u


def _case(session, owner, *, title="Credential stuffing", severity="high",
          status=AlertCaseStatus.CLOSED, reason="false_positive",
          created=NOW, closed=None, closed_by=None):
    c = AlertCase(
        case_number=_Seq.next(), title=title, severity=severity, status=status,
        created_by_id=owner.id, closure_reason=reason, created_at=created,
        updated_at=created, closed_at=closed,
        closed_by_id=closed_by.id if closed_by else None,
    )
    session.add(c)
    session.flush()
    return c


def _audit(session, user, *, when=NOW, action="alert.view"):
    e = AuditLog(user_id=user.id, action=action, timestamp=when)
    session.add(e)
    session.flush()
    return e


class TestEsc:
    """The only sanitiser between alert data and the mailed PDF."""

    def test_the_five_special_characters_are_escaped(self):
        assert _esc('<&>"\'') == "&lt;&amp;&gt;&quot;&#x27;"

    def test_a_script_tag_in_a_case_title_is_neutralised(self):
        out = _esc("<script>alert(1)</script>")
        assert "<script>" not in out
        assert out == "&lt;script&gt;alert(1)&lt;/script&gt;"

    def test_quotes_are_escaped_so_attribute_context_is_safe(self):
        """The severity value lands inside class="sev-...", so a bare quote
        would break out of the attribute."""
        assert '"' not in _esc('high" onload="evil()')

    def test_none_renders_as_empty_rather_than_the_word_none(self):
        assert _esc(None) == ""

    def test_non_strings_are_coerced(self):
        assert _esc(42) == "42"
        assert _esc(3.5) == "3.5"


class TestFmt:
    def test_an_iso_timestamp_is_made_readable(self):
        assert _fmt("2026-06-15T12:30:00") == "15 Jun 2026 12:30"

    def test_an_unparsable_value_is_passed_through_rather_than_crashing(self):
        """A broken timestamp must not take the whole report down."""
        assert _fmt("not a date") == "not a date"

    def test_a_non_string_is_stringified(self):
        assert _fmt(None) == "None"


class TestCaseMetrics:
    def test_the_core_figures_come_from_the_shared_helper(self, session, analyst):
        """These must agree with /soc-health for the same window, which is why
        they are delegated rather than recomputed here."""
        _case(session, analyst, created=NOW, closed=NOW + timedelta(hours=2),
              reason="false_positive")
        _case(session, analyst, created=NOW, closed=NOW + timedelta(hours=4),
              reason="true_positive")

        out = _case_metrics(session, CUTOFF)

        assert out["opened"] == 2
        assert out["closed"] == 2
        assert out["closure_reasons"] == {"false_positive": 1,
                                         "true_positive": 1}
        assert out["avg_mttr"] == 3.0

    def test_the_fp_rate_is_the_share_of_all_closures(self, session, analyst):
        """Historical meaning, kept deliberately: false positives over every
        closure, NOT over threat/not-threat dispositions only. The two differ
        and `case_metrics` names them apart so a caller cannot mix them up."""
        _case(session, analyst, closed=NOW, reason="false_positive")
        _case(session, analyst, closed=NOW, reason="true_positive")
        _case(session, analyst, closed=NOW, reason="duplicate")
        _case(session, analyst, closed=NOW, reason="not_applicable")

        # 1 of 4 closures, not 1 of the 2 dispositions.
        assert _case_metrics(session, CUTOFF)["fp_rate"] == 25.0

    def test_the_severity_mix_counts_cases_opened_in_the_window(self, session,
                                                               analyst):
        _case(session, analyst, severity="critical", created=NOW)
        _case(session, analyst, severity="high", created=NOW)
        _case(session, analyst, severity="high", created=NOW)
        _case(session, analyst, severity="low", created=BEFORE)

        assert _case_metrics(session, CUTOFF)["by_severity"] == {
            "critical": 1, "high": 2}

    def test_a_case_with_no_severity_is_counted_as_unknown(self, session,
                                                           analyst):
        """Dropping it would make the severity table disagree with 'opened'."""
        _case(session, analyst, severity=None, created=NOW)

        out = _case_metrics(session, CUTOFF)

        assert out["by_severity"] == {"unknown": 1}
        assert sum(out["by_severity"].values()) == out["opened"]

    def test_the_backlog_ignores_the_window(self, session, analyst):
        """Backlog is a point-in-time count: an old open case is still open."""
        _case(session, analyst, status=AlertCaseStatus.OPEN, created=BEFORE,
              reason=None)

        assert _case_metrics(session, CUTOFF)["open_backlog"] == 1

    def test_an_empty_estate_reports_zeroes_not_nulls(self, session):
        out = _case_metrics(session, CUTOFF)
        assert out["opened"] == 0 and out["closed"] == 0
        assert out["by_severity"] == {}


class TestAlertMetrics:
    def test_triage_entries_in_the_window_are_counted(self, session, analyst):
        for _ in range(3):
            session.add(AlertTriage(es_alert_id=_Seq.next(), status="triaged",
                                    assigned_to_id=analyst.id, created_at=NOW,
                                    updated_at=NOW))
        session.flush()

        assert _alert_metrics(session, CUTOFF)["total_triaged"] == 3

    def test_entries_from_before_the_window_are_excluded(self, session, analyst):
        session.add(AlertTriage(es_alert_id="old", status="triaged",
                                assigned_to_id=analyst.id, created_at=BEFORE,
                                updated_at=BEFORE))
        session.flush()

        assert _alert_metrics(session, CUTOFF)["total_triaged"] == 0

    def test_active_analysts_are_counted_once_each(self, session, analyst):
        other = User(username="bob", email="b@example.com", password_hash="x")
        session.add(other)
        session.flush()
        for uid in (analyst.id, analyst.id, other.id):
            session.add(AlertTriage(es_alert_id=_Seq.next(), status="triaged",
                                    assigned_to_id=uid, created_at=NOW,
                                    updated_at=NOW))
        session.flush()

        assert _alert_metrics(session, CUTOFF)["analysts_active"] == 2

    def test_unassigned_triage_does_not_inflate_the_analyst_count(self, session):
        session.add(AlertTriage(es_alert_id="x", status="new",
                                assigned_to_id=None, created_at=NOW,
                                updated_at=NOW))
        session.flush()

        out = _alert_metrics(session, CUTOFF)

        assert out["total_triaged"] == 1
        assert out["analysts_active"] == 0

    def test_an_empty_estate_reports_zeroes(self, session):
        assert _alert_metrics(session, CUTOFF) == {"total_triaged": 0,
                                                  "analysts_active": 0}


class TestTeamMetrics:
    def test_an_analyst_with_activity_is_listed(self, session, analyst):
        _audit(session, analyst, when=NOW)

        out = _team_metrics(session, CUTOFF)

        assert out["analysts"] == [{"username": "alice", "cases_closed": 0,
                                   "total_actions": 1}]

    def test_an_analyst_with_no_activity_is_omitted(self, session, analyst):
        """A table row of zeroes for every account on the system is noise."""
        assert _team_metrics(session, CUTOFF)["analysts"] == []

    def test_activity_from_before_the_window_does_not_count(self, session,
                                                            analyst):
        _audit(session, analyst, when=BEFORE)
        assert _team_metrics(session, CUTOFF)["analysts"] == []

    def test_an_inactive_account_is_excluded(self, session, analyst):
        """A departed analyst's past week should not appear in team performance."""
        analyst.is_active = False
        session.flush()
        _audit(session, analyst, when=NOW)

        assert _team_metrics(session, CUTOFF)["analysts"] == []

    def test_cases_closed_are_attributed_to_the_closing_analyst(self, session,
                                                                analyst):
        other = User(username="bob", email="b@example.com", password_hash="x")
        session.add(other)
        session.flush()
        _audit(session, analyst, when=NOW)
        _audit(session, other, when=NOW)
        _case(session, analyst, closed=NOW, closed_by=analyst)
        _case(session, analyst, closed=NOW, closed_by=analyst)
        _case(session, analyst, closed=NOW, closed_by=other)

        by_name = {a["username"]: a["cases_closed"]
                   for a in _team_metrics(session, CUTOFF)["analysts"]}

        assert by_name == {"alice": 2, "bob": 1}

    def test_a_closure_before_the_window_is_not_credited(self, session, analyst):
        _audit(session, analyst, when=NOW)
        _case(session, analyst, closed=BEFORE, closed_by=analyst)

        assert _team_metrics(session, CUTOFF)["analysts"][0]["cases_closed"] == 0

    def test_analysts_are_ordered_by_activity_descending(self, session, analyst):
        other = User(username="bob", email="b@example.com", password_hash="x")
        session.add(other)
        session.flush()
        _audit(session, analyst, when=NOW)
        for _ in range(3):
            _audit(session, other, when=NOW)

        names = [a["username"] for a in _team_metrics(session, CUTOFF)["analysts"]]

        assert names == ["bob", "alice"]


class TestNotableIncidents:
    def test_critical_and_high_cases_are_notable(self, session, analyst):
        _case(session, analyst, severity="critical", created=NOW)
        _case(session, analyst, severity="high", created=NOW)

        assert len(_notable_incidents(session, CUTOFF)) == 2

    def test_medium_and_low_cases_are_not(self, session, analyst):
        _case(session, analyst, severity="medium", created=NOW)
        _case(session, analyst, severity="low", created=NOW)
        _case(session, analyst, severity=None, created=NOW)

        assert _notable_incidents(session, CUTOFF) == []

    def test_cases_from_before_the_window_are_excluded(self, session, analyst):
        _case(session, analyst, severity="critical", created=BEFORE)
        assert _notable_incidents(session, CUTOFF) == []

    def test_the_newest_incident_comes_first(self, session, analyst):
        _case(session, analyst, severity="critical", title="older",
              created=NOW - timedelta(days=2))
        _case(session, analyst, severity="critical", title="newer", created=NOW)

        assert [i["title"] for i in _notable_incidents(session, CUTOFF)] == [
            "newer", "older"]

    def test_the_list_is_capped_at_fifteen(self, session, analyst):
        for i in range(20):
            _case(session, analyst, severity="high",
                  created=NOW - timedelta(minutes=i))

        assert len(_notable_incidents(session, CUTOFF)) == 15

    def test_an_incident_carries_what_the_table_shows(self, session, analyst):
        c = _case(session, analyst, severity="critical", title="Ransomware",
                  status=AlertCaseStatus.OPEN, created=NOW, reason=None)

        inc = _notable_incidents(session, CUTOFF)[0]

        assert inc == {"case_number": c.case_number, "title": "Ransomware",
                      "severity": "critical", "status": AlertCaseStatus.OPEN,
                      "created_at": NOW.isoformat()}


class TestTrends:
    def test_there_is_one_row_per_day_in_the_period(self, session):
        assert len(_compute_trends(session, CUTOFF, 7)["daily"]) == 7

    def test_the_days_run_forward_from_the_cutoff(self, session):
        daily = _compute_trends(session, CUTOFF, 3)["daily"]
        assert [d["date"] for d in daily] == [
            (CUTOFF + timedelta(days=i)).strftime("%Y-%m-%d") for i in range(3)]

    def test_cases_are_counted_on_the_day_they_opened(self, session, analyst):
        day = CUTOFF + timedelta(days=2, hours=5)
        _case(session, analyst, created=day)

        daily = _compute_trends(session, CUTOFF, 7)["daily"]

        assert daily[2]["opened"] == 1
        assert sum(d["opened"] for d in daily) == 1

    def test_cases_are_counted_on_the_day_they_closed(self, session, analyst):
        _case(session, analyst, created=CUTOFF,
              closed=CUTOFF + timedelta(days=4, hours=1))

        daily = _compute_trends(session, CUTOFF, 7)["daily"]

        assert daily[4]["closed"] == 1
        assert sum(d["closed"] for d in daily) == 1

    def test_a_day_boundary_does_not_double_count(self, session, analyst):
        """Each bucket is [day_start, day_start + 1 day), so a case created at
        exactly midnight belongs to the later day only."""
        midnight = (CUTOFF + timedelta(days=3)).replace(hour=0, minute=0,
                                                        second=0, microsecond=0)
        _case(session, analyst, created=midnight)

        daily = _compute_trends(session, CUTOFF, 7)["daily"]

        assert sum(d["opened"] for d in daily) == 1

    def test_a_zero_day_period_yields_no_rows(self, session):
        assert _compute_trends(session, CUTOFF, 0)["daily"] == []


class TestGenerateReport:
    def test_the_report_carries_every_section_the_renderer_reads(self, session):
        out = generate_executive_report(session)
        assert set(out) == {"generated_at", "period_start", "period_end",
                            "period_days", "cases", "alerts", "team",
                            "notable_incidents", "trends"}

    def test_the_default_period_is_a_week(self, session):
        out = generate_executive_report(session)
        assert out["period_days"] == 7
        assert len(out["trends"]["daily"]) == 7

    def test_the_period_is_configurable(self, session):
        out = generate_executive_report(session, days=30)
        assert out["period_days"] == 30
        assert len(out["trends"]["daily"]) == 30

    def test_the_period_start_is_the_requested_span_back(self, session):
        out = generate_executive_report(session, days=14)
        start = datetime.fromisoformat(out["period_start"])
        end = datetime.fromisoformat(out["period_end"])
        assert (end - start) == timedelta(days=14)

    def test_the_timestamps_are_timezone_aware(self, session):
        """The report is read in several offices; a bare local time is a lie."""
        out = generate_executive_report(session)
        assert datetime.fromisoformat(out["generated_at"]).tzinfo is not None


def _report(session, **over):
    """A fully-populated report dict, so the renderer tests do not depend on a
    particular database state."""
    base = {
        "generated_at": "2026-06-15T12:00:00",
        "period_start": "2026-06-08T12:00:00",
        "period_end": "2026-06-15T12:00:00",
        "period_days": 7,
        "cases": {"opened": 10, "closed": 8, "fp_rate": 25.0, "avg_mttr": 3.5,
                  "open_backlog": 4, "closure_reasons": {"false_positive": 6,
                                                         "true_positive": 2},
                  "by_severity": {"critical": 1, "high": 4, "medium": 3,
                                  "low": 2}},
        "alerts": {"total_triaged": 42, "analysts_active": 3},
        "team": {"analysts": [{"username": "alice", "cases_closed": 5,
                               "total_actions": 100}]},
        "notable_incidents": [{"case_number": "C-1", "title": "Ransomware",
                               "severity": "critical", "status": "open"}],
        "trends": {"daily": [{"date": "2026-06-08", "opened": 2, "closed": 1}]},
    }
    base.update(over)
    return base


class TestHtml:
    def test_the_document_is_self_contained(self, session):
        """It is converted to PDF with no network and no asset pipeline."""
        out = generate_executive_html(_report(session))
        assert out.startswith("<!DOCTYPE html>")
        assert out.rstrip().endswith("</html>")
        assert "<style>" in out
        assert "src=" not in out and "href=" not in out

    def test_the_headline_figures_appear(self, session):
        out = generate_executive_html(_report(session))
        for expected in ("ION Executive Report", ">10<", ">8<", "25.0%",
                         ">3.5<", ">4<", ">42<", ">3<"):
            assert expected in out, expected

    def test_the_period_is_stated_readably(self, session):
        out = generate_executive_html(_report(session))
        assert "08 Jun 2026 12:00" in out
        assert "15 Jun 2026 12:00" in out

    def test_a_high_false_positive_rate_is_flagged(self, session):
        """Over half of closures being false positives is the number leadership
        is meant to notice, so it is coloured rather than merely printed."""
        out = generate_executive_html(_report(
            session, cases={**_report(session)["cases"], "fp_rate": 60.0}))
        assert "stat-val crit" in out

    def test_a_normal_false_positive_rate_is_not_flagged(self, session):
        assert "stat-val crit" not in generate_executive_html(_report(session))

    def test_a_missing_false_positive_rate_renders_as_zero(self, session):
        out = generate_executive_html(_report(
            session, cases={**_report(session)["cases"], "fp_rate": None}))
        assert "0%" in out
        assert "stat-val crit" not in out

    def test_a_missing_mttr_renders_as_a_dash(self, session):
        out = generate_executive_html(_report(
            session, cases={**_report(session)["cases"], "avg_mttr": None}))
        assert ">-<" in out

    def test_a_large_backlog_is_flagged(self, session):
        out = generate_executive_html(_report(
            session, cases={**_report(session)["cases"], "open_backlog": 21}))
        assert "stat-val warn" in out

    def test_closure_reasons_are_tabulated_with_percentages(self, session):
        out = generate_executive_html(_report(session))
        assert "Closure Reasons" in out
        assert "False Positive" in out
        assert "75%" in out      # 6 of 8

    def test_closure_reasons_are_ordered_by_frequency(self, session):
        out = generate_executive_html(_report(session))
        assert out.index("False Positive") < out.index("True Positive")

    def test_an_empty_closure_table_is_omitted_rather_than_rendered_blank(
        self, session
    ):
        out = generate_executive_html(_report(
            session, cases={**_report(session)["cases"], "closure_reasons": {}}))
        assert "Closure Reasons" not in out

    def test_severities_are_listed_in_descending_order(self, session):
        out = generate_executive_html(_report(session))
        assert out.index("Critical") < out.index("High") < out.index("Low")

    def test_a_severity_with_no_cases_is_skipped(self, session):
        out = generate_executive_html(_report(
            session, cases={**_report(session)["cases"],
                            "by_severity": {"critical": 2}}))
        assert "Critical" in out
        assert ">Low<" not in out

    def test_the_team_table_is_omitted_when_nobody_was_active(self, session):
        out = generate_executive_html(_report(session, team={"analysts": []}))
        assert "Team Performance" not in out

    def test_the_team_table_shows_at_most_ten_analysts(self, session):
        analysts = [{"username": f"analyst{i}", "cases_closed": 0,
                     "total_actions": 1} for i in range(15)]
        out = generate_executive_html(_report(session,
                                              team={"analysts": analysts}))
        assert "analyst9" in out
        assert "analyst10" not in out

    def test_the_incident_table_is_omitted_when_there_were_none(self, session):
        out = generate_executive_html(_report(session, notable_incidents=[]))
        assert "Notable Incidents" not in out

    def test_the_incident_table_shows_at_most_ten(self, session):
        incidents = [{"case_number": f"C-{i}", "title": f"inc{i}",
                      "severity": "high", "status": "open"} for i in range(15)]
        out = generate_executive_html(_report(session,
                                              notable_incidents=incidents))
        assert "inc9" in out
        assert "inc10" not in out

    def test_the_trend_table_is_omitted_when_empty(self, session):
        out = generate_executive_html(_report(session, trends={"daily": []}))
        assert "Daily Activity Trend" not in out

    def test_a_report_with_nothing_in_it_still_renders(self, session):
        """A quiet week must produce a valid document, not a traceback."""
        out = generate_executive_html(generate_executive_report(session))
        assert out.startswith("<!DOCTYPE html>")
        assert out.rstrip().endswith("</html>")


class TestHtmlEscaping:
    """Case titles originate in alert data; this document is mailed outward."""

    def test_a_hostile_case_title_is_escaped(self, session):
        out = generate_executive_html(_report(session, notable_incidents=[{
            "case_number": "C-1", "title": "<script>alert(1)</script>",
            "severity": "high", "status": "open"}]))

        assert "<script>" not in out
        assert "&lt;script&gt;" in out

    def test_a_hostile_severity_cannot_break_out_of_its_attribute(self, session):
        """severity lands inside class="sev-...", the one attribute context."""
        out = generate_executive_html(_report(session, notable_incidents=[{
            "case_number": "C-1", "title": "t",
            "severity": 'high" onmouseover="evil()', "status": "open"}]))

        assert 'onmouseover="evil()"' not in out
        assert "&quot;" in out

    def test_a_hostile_username_is_escaped(self, session):
        out = generate_executive_html(_report(session, team={"analysts": [
            {"username": "<img src=x onerror=1>", "cases_closed": 0,
             "total_actions": 1}]}))

        assert "<img" not in out

    def test_a_hostile_closure_reason_is_escaped(self, session):
        out = generate_executive_html(_report(
            session, cases={**_report(session)["cases"],
                            "closure_reasons": {"<b>x</b>": 1}}))

        assert "<b>x</b>" not in out


class TestPdf:
    @pytest.mark.requires_weasyprint
    def test_a_pdf_is_produced(self, session):
        pdf = generate_executive_pdf(_report(session))
        assert pdf is not None
        assert pdf.startswith(b"%PDF")

    def test_a_missing_renderer_yields_none_rather_than_an_exception(
        self, session, monkeypatch
    ):
        """WeasyPrint needs system libraries ION cannot assume in an air-gapped
        deployment, so the caller must get None and fall back to HTML."""
        monkeypatch.setitem(sys.modules, "weasyprint", None)

        assert generate_executive_pdf(_report(session)) is None
