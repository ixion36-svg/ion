# Archived feature clusters

Code that ION no longer ships, kept here so it can be read and recovered
without digging through git history. Nothing in this directory is live:

- **not linted** — `exclude = ["archive"]` in `[tool.ruff]`
- **not packaged** — `[tool.setuptools.packages.find]` reads `src/` alone
- **not tested** — `[tool.pytest.ini_options] testpaths = ["tests"]`
- **not built** — `archive/` is in `.dockerignore`

Nothing under `src/` may import from here. If something does, the archive
boundary has leaked and the import is the bug, not the exclusion.

| Cluster | Archived | What it was |
|---|---|---|
| `courseware/` | v0.99.5 | L1–L4 SOC training courses: enrolment, lessons, quizzes, PDF certificates, the scored training simulator, and the 1.4 MB course seed. |
| `cyber_range/` | v0.99.5 | Hands-on lab exercises and the Kali/DVWA/JuiceShop range: lab grading and sessions, replayable lab fixtures, and the range compose file. Adversary emulation was archived here in error and restored to `src/` — it verifies that expected detections fired, so it belongs to Detection Engineering. |
| `cyab/` | v0.99.5 | CyAB — the system onboarding and assurance workbench: the assessment questionnaire, sub-profile catalogue, scoping and onboarding wizards, documentation checklist, sign-off packs, fleet coverage matrix and audit feed, plus the whole `/cyab` UI. |
| `unwired/` | v0.99.5 | Seven services nothing ever called, found by the first coverage run: AI document analysis (superseded by `large_doc_service`), email notifications and the SMTP service under them, SLA policies, the change log, dashboard layouts, and saved searches (superseded by `SavedSearchRepository`). With their five model classes and the three email templates. |

The two were archived together because they are one subsystem: labs are
LAB-type lessons inside seeded courses, `labs_api` resolved them through
`Course`, and `seed_lab_fixtures.py` runs only after `seed_courses.py`.

### Why `unwired/` is different

The other three clusters were working features someone decided to stop
shipping. These seven were never reachable at all: no route, no caller, no
test, in any released version. The coverage ratchet found them — they were
the only modules at 0% with nothing importing them.

`smtp_service` went with them by cascade: `notification_service` was its only
caller, so sending mail became unreachable the moment that left. If email is
wanted later, both come back together.

Two were superseded rather than abandoned. `/saved-searches` is live and
always went through `storage/saved_search_repository.py`; `saved_search_service`
was a second implementation nothing picked up. `large_doc_service` does what
`ai_document_service` describes.

Not archived, but dead by the same test and worth a decision: `OnCallRoster`,
`EscalationPolicy` and `EscalationLog` in `models/oncall.py` have zero
references anywhere, and `models/__init__.py` does not even export them.

### What CyAB left behind in `src/`

Two pieces stayed, because live features read them rather than the CyAB UI:

- `models/cyab.py` — `CyabSystem` and `CyabDataSource` are the asset registry.
  A data source carries the Elasticsearch `data_namespace` and the
  `tide_system_id` it maps to.
- `services/system_resolver_service.py` — resolves an alert's `source_system`
  namespace through that registry to a CyAB system *and a TIDE system*.
  `elasticsearch_api` stamps `cyab_system_name` and `tide_system_id` onto
  every alert in the queue from it, and `analytics_api` and `de_tide_api`
  read the same tables to scope TIDE rules and use cases.

So the registry tables are live data, not archive fodder. What left was the
workbench on top of them: the questionnaire, sub-profiles, wizards,
checklists, sign-off and the `/cyab` pages. `CyabSnapshot`, `CyabAssessment`
and `CyabSystemAssessment` stay declared in `models/cyab.py` even though
nothing reads them now, because their tables hold data.


## Restoring

Each cluster keeps its original layout under its own directory, so a file
goes back roughly where it came from (`web/`, `services/`, `models/`,
`templates/`, `tests/`). Restoring also means putting back the router
imports and `include_router` calls in `src/ion/web/server.py`, the page
routes, the nav entries in `templates/base.html`, and any model exports in
`src/ion/models/__init__.py`.

The database tables these features used were deliberately left in place:
dropping them would destroy analyst-authored content, so that is an
operator decision. `courses` and `course_enrolments` are still live —
the workforce onboarding journey reads them to resolve COURSE requirements.
