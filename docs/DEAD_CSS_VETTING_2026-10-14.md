# Dead CSS vetting, 2026-10-14

Base release `9edf38f91f3c10ba3884fbc69187b0eb02bec0d6`.
Branch `codex/dead-css-vetting`.

This review removes 318 individually approved whole rules. Of those, 316 came
from the 384 newly exposed rules; two were previously mapped PCAP hash replacements.
No strict deletion, mixed-selector splitting or scanner `--write` was used.

The release scanner reported 393 candidate classes and 428 removable whole rules.
The manifest records every baseline rule touching those classes, including rules
that were never wholly removable: **535 records, 318 REMOVE and 217 KEEP**.
The corrected scanner reduced whole-rule candidates from 428 to 347 before any
CSS was cut. Its remaining candidates are work for another review, not a deletion list.

## Rules removed and kept

The KEEP column counts all candidate-touching rules, including mixed compounds
and comma lists. It is broader than the original scanner's removable-rule count.
Every selector and original rule hash appears in
[the per-rule manifest](dead-css-vetting-2026-10-14.json).

| Sheet | Removed | Kept | Reason for keeping |
| --- | ---: | ---: | --- |
| cases-page.css | 82 | 25 | Shared alert-detail host prefix, conservative families and mixed compounds. |
| alerts-page.css | 67 | 19 | Conservative prefixes and mixed selectors. |
| chat-page.css | 62 | 1 | Mixed compound. |
| integrations-page.css | 32 | 19 | Conservative prefixes and mixed active-flow selectors. |
| forensics-page.css | 21 | 2 | Conservative prefix retention. |
| analytics-page.css | 9 | 42 | Live Python colours, macro closure colours, namespace formats and mixed selectors. |
| settings-page.css | 11 | 5 | Conservative settings/env/session families. |
| observables-page.css | 14 | 8 | Context-badge compounds and a mixed comma list. |
| playbooks-page.css | 7 | 2 | Conservative exec family and mixed selector. |
| discover-page.css | 2 | 7 | Conservative search family, mixed containers and compound selectors. |
| pcap-page.css | 5 | 15 | Python protocol/tone/TI classes and mixed selectors. |
| arkime-traffic.css | 2 | 1 | Mixed `.jvectormap-tip.active`; current vendor emits `jvm-*`. |
| templates-page.css | 2 | 0 | No retained candidates. |
| ion-migrated-styles.css | 2 | 13 | Other migration hashes lack independently verified named replacements. |
| ion-shell.css | 0 | 4 | Escaped slash utility names are parser artefacts; bg-grid is in a mixed selector. |
| threat-intel.css | 0 | 12 | Conservative ti-prefix retention. |
| ion-legacy.css | 0 | 8 | Previously covered build input, outside the new-rule tranche. |
| ion-pages.css | 0 | 34 | Same scope boundary; live Python IQ pills also protected. |

The two removed hashes are `_ion-s-7554583028` and `_ion-s-b17605f04d`.
Their existing `replaced_by` claims name `.pcap-ti-chip` and `.pcap-ti-link`;
the matching definitions and Python producer remain. No map entry was reflowed
or replaced with an invented claim. The other 13 hash candidates remain intact.

## Scanner corrections and live false positives

- Python view models now join the source corpus. Analytics FP bands and named
  namespaces, PCAP protocol/tone/TI classes and investigation-queue pills were
  invisible to the release scanner.
- Percent-format prefixes cover the real `"ns-p%d" % (...)` namespace fallback.
- Python f-string prefixes are conservatively recognised.
- Standalone literal prefixes protect Jinja macros that join
  `{{ prefix }}{{ s.key }}` after receiving `'cl-'`.
- Shared alert-detail `classPrefix` options and defaults protect `_cls()` output.
  In particular, `cpanel-alert-fields-table` is emitted from the cases host prefix;
  `cpanel-alert-showall` is dynamically queried and is conservatively kept.

Five new scanner regressions cover these gaps. Four initial tests were observed
failing, then the host-prefix test failed separately before its fix. Prefix
retention deliberately keeps more than the runtime-proven live classes. It is
not evidence that every retained old wrapper still renders.

[The source evidence](DEAD_CSS_VETTING_EVIDENCE_2026-10-14.md) lists exact classes,
producer snippets, obsolete builder history, unknown-joiner classification and
page-specific gates. All templates, fragments, static JS and Python under
`src/ion` were searched. Unknown first-party joiners were traced rather than
assumed safe; the alert-detail joiner led to the prefix fix.

## Reproducible proof

Run `python tools/check_dead_css_vetting.py`. It compares against the immutable
release Git blobs, verifies complete candidate-touching rule coverage, checks
selector hashes and class lists, rejects mixed/complex removal policy, rechecks
current source reachability, and requires every other stylesheet byte to match.
Five control tests prove it rejects a missing record, a falsified empty class
list, a new source reference and an unapproved change to a retained rule.

An intermediate inventory regeneration mistakenly read already-cut sheets.
That scratch result was discarded. Generation now reads immutable release CSS;
independent review and the committed checker verify the corrected manifest.
No deletion was authorized by the incomplete intermediate inventory.

The [decision log](DEAD_CSS_VETTING_DECISIONS_2026-10-14.tsv) was compiled
retrospectively through the cuts phase. Its initial timestamps record when the
rows were written, not when those actions occurred. Later rows append verification
and correction evidence. The log does not independently prove event ordering.

## Verification

All 14 per-sheet runs passed scanner, sheet-coverage, page-specific and
CSS-current gates. The pinned Tailwind binary was present; no rebuild or
`ion.css` change was needed. The rewrite audit reports **0 problem(s)** and
`tools/ui_rewrite_baseline.json` is unchanged. Scoped lint passes.

| Per-sheet gate run | Passed tests |
| --- | ---: |
| Cases | 466 |
| Alerts | 607 |
| Chat | 95 |
| Integrations | 223 |
| Forensics | 231 |
| Analytics | 239 |
| Settings | 110 |
| Observables | 133 |
| Playbooks | 99 |
| Discover | 100 |
| PCAP | 186 |
| Arkime traffic | 56 |
| Templates | 211 |
| Migrated styles | 188 |

These are separate runs with shared tests, not a count of unique tests. A final
29-test proof/scanner/coverage/CSS-current run also passes after removing
indentation from newly empty selector lines. Retained declarations are unchanged.

Browser comparison passed **58 unique state/theme pairs**, with **116 HTTP 200
navigations**. All pairs have identical element counts, computed styles,
geometry and full-page screenshot pixels. There were no uncaught page errors
or failed requests in the selected final samples. Opened both themes on `/cases`,
`/alerts`, `/chat`, `/integrations`, `/forensics`, `/analytics`, `/settings`,
`/observables`, `/playbooks`, `/discover`, `/pcap`, `/arkime-traffic` and `/templates`.
Additional tab/modal states and actual emitted `cpanel-alert-fields-table`,
`ns-windows` and `ns-p1` elements were compared.

The browser fixture uses a private SQLite backup, authentication overrides,
secret-free defaults and controlled read responses. It replays identical fragment
HTML to isolate CSS from live metrics. It does not verify live integrations,
login, populated PCAP findings/IKE/TI, Arkime map interactions or every popup.
No PCAP was fabricated or uploaded. Twelve fixture EventSource MIME warnings
occurred in both CSS modes; there were no page errors. Transition sampling,
client clock and request-close timing issues in early comparisons were corrected
in the harness without application changes. Final CSS hashes were checked after
normalizing only empty-line indentation; all 35 served sheets matched the
captured comparison bytes under that normalization. The fixture server is stopped.

Local raw evidence is in `.audit/css-browser-summary.json`,
`.audit/css-browser-report.md`, screenshots and `.audit/*-gates.txt`.
Independent source/proof review found no unsafe cut or unclaimed hash loss.
The trail review found coarse initial evidence pointers and retrospective
timestamps; supplementary rows and the limitation above make those explicit.

The full suite completed with exit code **0** using 12 workers, `--dist loadfile`,
unbuffered output, disabled random ordering and a private basetemp:
**11,862 passed, 32 skipped, 2 xfailed, 2 xpassed, 0 failed** in **1,402.81 seconds**.
The release baseline was 11,851 passed, 33 skipped, 2 xfailed and 2 xpassed.
This branch adds ten tests; total outcomes increase by ten. The exact skip/pass
distribution differs by one existing test, whose identity is not established by
the baseline's aggregate numbers. No parallel failure needed a standalone rerun.

The run reports 2,232 warnings, two background case-grouper logging errors from
writing an unconfigured-Elasticsearch warning to a closed stream, and a WeasyPrint
external-library notice. Those service/library paths are untouched by this change;
they were recorded rather than repaired outside the CSS scope. Raw full output is
`.audit/full-suite.log`. The final eight standard UI gates also pass **261 tests**.

The Build the Lever principle produced the committed removal checker and manifest.
Prove It Works required the real-page CSS comparisons and completed full-suite
process, rather than inferring safety from the scanner's candidate count.
