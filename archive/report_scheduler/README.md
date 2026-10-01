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

## The model went too

`ScheduledReport` has since been removed from `src/ion/models/sla.py` and the
`scheduled_reports` table is dropped by the idempotent sweep in
`storage/database.py` (ION has no Alembic; that sweep is where schema changes
live, alongside the `notifications`, `threat_hunts` and `kb_document_embeddings`
drops that set the pattern). So the `from ion.models.sla import ScheduledReport`
at the top of this module no longer resolves.

That is expected of archived code and matches `archive/courseware/`, whose
modules import archived models. Reviving this module means restoring the model
and the table alongside it — at which point `scheduler_service` is almost
certainly the better place to put the work.

## What is kept live

`_dispatch_report` called four services that are all still live and now tested:
`executive_report_service`, `soc_health_service`, `shift_handover_service` and
`compliance_mapping_service`. Nothing was lost by archiving the dispatcher.
