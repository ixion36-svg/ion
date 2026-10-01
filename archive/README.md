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
| `cyber_range/` | v0.99.5 | Hands-on lab exercises and the Kali/DVWA/JuiceShop range: lab grading and sessions, replayable lab fixtures, adversary emulation, and the range compose file. |

The two were archived together because they are one subsystem: labs are
LAB-type lessons inside seeded courses, `labs_api` resolved them through
`Course`, and `seed_lab_fixtures.py` runs only after `seed_courses.py`.

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
