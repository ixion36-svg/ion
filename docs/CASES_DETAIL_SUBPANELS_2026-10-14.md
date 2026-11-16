# Cases detail subpanels verification — 2026-10-14

Branch: `codex/ui-redesign-cases-detail`. Base: `61d2415e39281e650024bc25f1a7ac54b6f8044a`.
Worktree: `C:/Users/lyndo/projects/ion-sol-detail`.

The nine scoped functions now load eight server-rendered fragment routes.
`tools/ui_redesign_status.py` measures **37 → 21 runtime writes** in `cases.html`.
The 16 removed writes belong exclusively to these nine functions. All other
named JavaScript functions and the 2,163-line stylesheet remain byte-for-byte
unchanged. `renderAnnotations` is deleted; its caller uses the annotation fragment.
Detail core, closure, attack path, workbench and playbooks browser remain unchanged.

## Failure and empty states

| Function | Failure behavior |
| --- | --- |
| `loadProcessTreeInto` | Preserves the failure prefix and unavailable state; transport failures use a stable message rather than exposing exception text. Genuine empty trees remain empty. Successful and unavailable reads retain caching. |
| `loadKibanaComments` | Preserves “Could not load Kibana comments”; failed count is unknown (`-`), successful empty is zero. |
| `loadRuleGuideInto` | Preserves the failure prefix with a stable message; no raw data and no guide remain distinct empty states. Shares the existing raw fetch with fields/raw panels. |
| `loadResponseActionLog` | Preserves “Could not load action log.” HTTP errors and malformed bodies no longer become “No actions requested yet”; only a successful empty array does. |
| `loadAnnotations` | Preserves “Failed to load annotations”; failed count is unknown. Existing edit/add/delete callbacks and form toggle work. |
| `loadCaseSyncStatus` | Replaces silent failure with explicit unknown/error. Missing or contradictory counts cannot produce a warning or quiet zero. Known zero remains quiet; retry-only is warning; abandoned is error. |
| `loadResponseActions` | Preserves “Could not load response actions.” Only explicit feature-disabled state removes the section. Successful empty applicability remains empty. |
| `renderAnnotations` | Deleted; rendering and failure states now belong to the annotation fragment and loader. |
| `translateCaseNote` | Preserves the bracketed translation-failed convention using stable transport text or escaped provider detail. Original nodes survive retries; toggle-off restores clones without another translation call. |

Shared UTC helpers now label owned subpanel timestamps consistently. Data and
action arguments are escaped, Markdown still passes through DOMPurify, and
permission checks precede direct source calls. Response execution and annotation
mutations continue through their existing APIs.

## Empty-array decisions

The converted paths validate collection shape instead of treating missing data
as `[]`. Explicit comments, annotations and log arrays may be genuinely empty;
missing/malformed collections fail. Missing catalogue actions or malformed supplied
observables fail. An unsupported observable type has no applicable actions and is
an intentional empty match. The successful case-detail API explicitly supplies an
observables array. Its existing `openCaseDetail` caller still uses
`c.observables || []`, outside this task's permitted function scope.

Two upstream boundaries remain lossy: `get_case_comments` collapses disabled,
HTTP-error, exception and missing-key results to `[]`, which the API presents as
comments; the shared raw-alert helper resolves HTTP error JSON to null. The new
fragments cannot recover those distinctions. A second raw request would break
coalescing, so no duplicate request was introduced.

| Previous fallback | Decision |
| --- | --- |
| `data.comments || []` | Explicit array only; missing/non-list fails. Upstream service swallowing remains as described above. |
| `data.annotations || []` | Explicit array only; missing/non-list fails. |
| `d.unresolved || []` | Explicit array and consistent measured counts required; unknown is error. |
| `catalog.actions || []` | Explicit array only; unreadable catalogue fails. |
| `observables || []` | Supplied array required by fragment; unchanged core caller fallback is deferred. |
| `_RESPONSE_APPLIES[type] || []` | Real empty applicability for an unsupported type. |
| `response.log || []` and non-OK `: []` | Explicit successful array only; HTTP and malformed results fail. |

## Verification

Tests were observed failing before implementation: route 404s, Form encoding 422s,
and nine client-scope failures with the positive/negative control passing.
The final combined run passes **353 tests**: **93** targeted tests and **260**
tests from the eight mandatory gate files, with the pinned Tailwind binary present
and no skipped CSS checks. The fresh CSS comparison passes without rebuilding.
The rewrite audit reports **0 problems**. Scoped Python lint passes.
Independent security review found no scoped correctness or security defect;
its requested route-surface assessment delta is included.

Browser verification used the actual case-detail page, real htmx/CSP and isolated
database snapshots with controlled source adapters: **39 process/guide checks**
(including eight authenticated/anonymous permission checks), **37 notes checks**,
and **28 response/sync checks**. Coverage includes data/empty/failure states,
escaping, copy/pin and annotation/action callbacks, UTC labels, translation
restoration and selected same-target request races. Four screenshots per group
cover desktop/mobile and dark/light themes. Fixtures were stopped afterward.
These checks do not verify live Elasticsearch, Kibana, translator or response
systems, nor the login/session lifecycle.

No uncaught page errors occurred. Two initial `style-src-attr` warnings reproduce
with the entire unchanged baseline cases template, with identical count/hash;
controlled removal of htmx's style-settling attribute also eliminates them.
Scoped swaps introduced no additional CSP violation. Deliberate denied requests,
network failures, race cancellations and a sanitized image's missing URL explain
the remaining expected console records.

## Deliberately deferred

- Remaining 21 writes, core `ageLabel`/`fmtDate` UTC behavior and core observable fallback.
- Existing light-theme Markdown white text and mobile workbench clipping; CSS is outside scope.
- Existing shared htmx style-settling CSP warnings and lossy upstream reads described above.
- Dead string-rendering helpers outside the nine permitted functions.
- Whole-source lint has 20 diagnostics in untouched files; only scoped lint is clean.

Detailed fixture scripts, screenshots, results and baseline scope proof are retained
locally under `.audit/`; they are excluded from the commit.
