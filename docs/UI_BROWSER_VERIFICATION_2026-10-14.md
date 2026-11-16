# UI browser verification, 2026-10-14

Branch: `codex/ui-browser-verification`.
Base: `7a69dee225c7ab73e53aab92a872961a91fbd019`.
Worktree: `C:/Users/lyndo/projects/ion-gpt-verify`.

Chromium exercised the real app, routers, view builders, htmx, delegated
actions, dynamic-style observer and strict CSP. The server imported this
worktree's `src`, with a private SQLite backup of the existing dev database;
no SQLite `ION_DATABASE_URL` was set. Passwords and session storage remain
outside version control. The primary checkout and other workers' files were
not changed.

The dev configuration has no Elasticsearch or available AI provider.
Supplemental runs supplied known read results or controlled SSE responses to
exercise nonempty rendering. These are wiring checks, not evidence that a live
Elasticsearch query or model generation succeeded.

## Coverage

| Page | Exercised and passing |
|---|---|
| Analytics | All **nine** tabs, seven summary tiles, overview/config, all systems OOB targets, index/coverage widths, risk/noise bars, metric sparks, timeline, failed refresh, mobile and desktop layouts in both themes. |
| Discover | Search, histogram, indices, mappings, field statistics, single/bulk IOC hunts, saved-search lists, OOB headers/counts/summaries and measured histogram heights. Actual unconfigured-ES states and supplemental nonempty results. |
| Chat | All contexts/quick prompts; actual file upload/view/Edit/Cancel; settings; controlled completed streams with citations, grounding and feedback; Markdown/HTML/plain document previews; split JSON, metadata and multibyte UTF-8 chunks. |
| Documents | Actual library filters, document detail/source/Quill, history and version headers including OOB revert controls, folder management, collection-read failure recovery, and clickable modal Close controls at both sizes/themes. |
| PCAP | Real capture upload, history/reopen, six stored-job fragments, DNS/Data Transfer retention, populated optional tabs, delegated tab clicks, graph and computed widths. Supplemental findings exercise filtering, case options and the existing attachment request with original stored finding indexes. |

The capture was the user's confirmed genuine
`C:/Users/lyndo/Downloads/ion-capture.pcapng` (46,757,264 bytes), parsed into
**42,035 packets**. No capture was generated or taken from `test_pcaps/`.
The real capture had no heuristic findings; attachment/filter wiring therefore
used a clearly separate stored-result fixture. Its mutation response was
intercepted: no fixture findings were pinned into a real evidence ledger.

## Findings and repairs

| Page and reproduction | Browser/network evidence | Repair |
|---|---|---|
| Discover: search, mapping/statistics and IOC results | HTTP 200, but zero `tr` elements; row text flattened into the body. | Enable template fragments and put rows before non-table OOB nodes in all five affected fragments. |
| Discover: first saved-search click | Panel stayed hidden; second click opened it. | Test computed visibility. |
| Analytics: successful systems read followed by HTTP 500 | Prior figures/timeline persisted and cards stayed “Loading”. | Clear dependent figures and replace all stale OOB regions with explicit unknown/failure state on htmx errors. |
| Analytics: systems at 390px | Fixed six columns clipped labels; 420px cards exceeded the available width. | Responsive stats columns and card minimum bounded by container width. |
| Chat: first Knowledge Sources click | Panel stayed hidden. | Test computed visibility. |
| Chat: click an uploaded file | No viewer request or modal. | Bind escaped JSON action arguments to the existing viewer. |
| Chat and document generation: split an SSE JSON event | Content disappeared; full-event positive control worked. | Carry unfinished lines and preserve decoder state across UTF-8 chunks in both readers. |
| Documents: refuse collection JSON read | Documents loaded, but folder sidebar stayed blank and its fragment was never requested. | Request the folder fragment independently in `finally`. |
| Documents: click Manage Folders Close | Hit test reached the navbar, including after raising modal z-index. | Mount plain modals outside the page wrapper's stacking context and above navigation. |
| PCAP: reopen real analysis | DNS/Data Transfer OOB content was overwritten by the final main swap. | Use `swap: 'none'` for these OOB-only responses. |
| PCAP: populated Hosts/Streams/JA4 | Rows existed in hidden, unreachable panels. | Return replacement optional tab buttons with state-derived visibility. |
| PCAP: select a severity chip | Cards did not filter. | Delegate the existing filter handler on the persistent findings panel. |
| PCAP: attach findings | Picker/button absent and functions unbound. Direct picker source also failed with “limit and offset must be integers”. | Restore controls under `case:read` + `case:update`, bind existing actions, check `case:read` before querying, pass concrete `offset=0`. Existing mutation API remains authoritative. |
| PCAP: mobile findings layout | Long case titles overflowed the picker, and severity chips stacked despite spare width. | Bound picker width and restore a wrapping chip row. |
| PCAP: load page with previous analyses | History was inaccessible until a new upload. | Load history initially and make its populated panel reachable. |

Regression checks failed before repair, including native Chromium parsing,
stream splitting and hit tests. `tests/unit/test_ui_browser_wiring.py` adds
route/markup contracts and positive/negative regex controls. Existing PCAP
tests now give attachment actors their required permissions.

## Errors and limits

- The real AI stream returns **503** with its browser resource error. Live model
  completion remains unverified; controlled SSE checks pass.
- The HTML sanitization probe deliberately requested `/x`, producing **404**.
  Its event handler was removed; no script executed.
- Injected systems **500** produced the browser resource error and htmx
  “Response Status Error Code 500”. The repaired page clears stale data.
- Injected collections **403** produced its resource error and the app's
  “Failed to load collections” log. The folder fragment now still renders.
- The initial reconnaissance runner used a string-expression wait that hit
  CSP's `unsafe-eval` restriction. A selector wait replaced it. Final app checks
  have no CSP violations or uncaught page errors.
- Two broader Analytics tests already fail at the untouched base: one bans a
  valid UI label string anywhere in the module; another expects a severity rule
  still to live inline after its stylesheet was moved. They were reproduced at
  `7a69dee2` and left unchanged. Evidence: `.audit/baseline-stale-tests.txt`.

Protected `cases.html`, `analytics_api.py`, and `chat_grounding_service.py` were
left untouched. No configuration boundary, secret handling, route, dependency
or permission grant changed. The four deliberate chat writes and three Quill
writes remain; Analytics, Discover and PCAP retain zero runtime writes.

## Verification evidence

The required seven-file gate set passes **164 tests, no skips**, including a
fresh pinned Tailwind build. `ui_rewrite_audit.py --check` reports **0 problems**;
its baseline was not rewritten. Route/status documentation was regenerated.
Security review found no remaining concerns.

Local replay scripts, red/green results, request/error records and screenshots
are in `.audit/analytics_discover_*`, `.audit/chat_docs_*`, `.audit/pcap_*`, and
`.audit/pcap-results.json`. They remain local because the browser state and
screenshots may contain dev data. No secret values are included in this report.
