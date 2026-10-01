# report_scheduler_service — archived

Fixed-schedule (daily / weekly / monthly) report generation, orphaned by the
v0.26.0 route audit and found by the coverage ratchet at **0% with 128
statements**.

## Why it is here

The audit removed six routers with zero references, `report_scheduler_api`
among them, and the CHANGELOG recorded that

> The `playbook_action` / `report_scheduler` / `smtp` **services remain** —
> they are used elsewhere; only the unused HTTP surface went.

That was true of `playbook_action_service` (still imported by
`web/response_api.py`) and `smtp_service` was archived later anyway. It was
never true of this module: nothing has imported it since its router went. The
only two mentions left in the tree are prose in other modules' docstrings
(`briefing_service`, `scheduler_service`), and the latter exists to say this one
is *not* the live scheduler.

`scheduler_service` is: generic 5-field crontab expressions, a handler registry,
an advisory-locked single-worker loop, `JobExecution` rows, and a wired
`scheduler_api`. It supersedes this module in every respect. Anything that
needs a daily report should register a handler there.

## What is kept live

`ScheduledReport` (`src/ion/models/sla.py`) stays declared even though this was
its only reader. The `scheduled_reports` table exists in deployed databases;
dropping the model would take it out of `Base.metadata` and out of step with the
migration history, which is how the CyAB `data_sources` FK drifted. Retiring the
model and the table is a migration, not an archive move.

`_dispatch_report` called four services that are all still live and now tested:
`executive_report_service`, `soc_health_service`, `shift_handover_service` and
`compliance_mapping_service`. Nothing was lost by archiving the dispatcher.
