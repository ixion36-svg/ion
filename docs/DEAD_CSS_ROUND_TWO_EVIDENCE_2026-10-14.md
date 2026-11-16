> Correction after browser verification: the initial review below missed the
> live `.sys-sev-pill` constructed by the analytics `sev_pills` macro. Its
> deletion approval and the subsequent blanket safety verdicts are superseded.
> The rule was restored; scanner macro-flow detection and a regression were
> added. The final manifest has 62 REMOVE / 95 KEEP, rather than 63 / 94.
> Retained historical review text documents the blind spot; it is not evidence
> that this live rule is dead. See the main report for final verification.

# CSS round-two page sheet independent review

Read-only review against base 74d034481588bb55cd02612961fa6395f55c82e0. No app/CSS/test changes made.

All 43 whole-rule removals below approved. KEEP means whole original rule, including mixed comma selectors, survives. No candidate proved live.

## Evidence method

Checked exact candidate tokens across all templates including fragments, static JavaScript, and every Python file under src/ion (expanded beyond scanner UI-only corpus). Checked language-specific constructed families over the same expanded Python corpus; no candidate has a literal class token. Expanded-source prefix collisions were independently traced: alerts- is an Elasticsearch .alerts-security.alerts-{space_id} index name (case_grouper_service.py:491, kibana_sync_helpers.py:98, case_lifecycle_api.py:335); s arises from logger %s%s (safe_errors.py:64,67 and server.py:696); m/c arise from strftime format %m%d or shell stat -c%s inside knowledge-base prose/export filenames. None emits a DOM class. Therefore no meaningful class construction reaches these candidates. Independently inspected current page markup replacements and relevant runtime class assignment sites described below. Scanner output supplies the worklist, not the decision.

The 46 unresolved joins were enumerated with source locations. Application joins are cases command-map keys, evidence-ID deduplication, annotation element IDs, chat message IDs, daily-work dates, security dashboard severity/status classes, and alert-detail injected alert-parsed/cpanel-alert families. None reaches these candidates. Vendored chart/cytoscape/mermaid/vis/map joins are internal property/ID/arrow-prefix constructions and are unrelated to these handwritten page families. Security dashboard _badge kind is explicitly severity/status at its only callsites (security_dashboard.py:359,362).

Substring search collisions do not represent literal classes: ti-page in multi-page prose; sortable in sortable_fields; timer-icon in timer-icon-pause; settings-nav in settings-nav-item; sys-sev-pill inside ad-sys-sev-pill. No CSS prefix selector relies on deleting these base classes.

## threat-intel.css

Approve 12 whole rules; retain 0 candidate-touching mixed rules.

Candidates: `ti-header`, `ti-page`, `ti-search-bar`, `ti-search-input`, `ti-stat-card`, `ti-stat-label`, `ti-stat-value`, `ti-stats`.

REMOVE selectors:

- `.ti-page`
- `.ti-header`
- `.ti-header h1`
- `.ti-header p`
- `.ti-stats`
- `.ti-stat-card`
- `.ti-stat-value`
- `.ti-stat-label`
- `.ti-search-bar`
- `.ti-search-input`
- `.ti-search-input::placeholder`
- `.ti-search-input:focus`

KEEP selectors (at least one independently live class, no splitting):

- None.

## integrations-page.css

Approve 7 whole rules; retain 12 candidate-touching mixed rules.

Candidates: `flow-fork-arm-line`, `flow-fork-stem`, `flow-merge-arm-line`, `flow-merge-stem`, `topo-detail-icon`, `topo-header`, `topo-header-actions`, `topo-page`, `topo-page-wrap`.

REMOVE selectors:

- `body[data-page="integrations"] .topo-page-wrap`
- `body[data-page="integrations"] .topo-page`
- `body[data-page="integrations"] .topo-header`
- `body[data-page="integrations"] .topo-header h1`
- `body[data-page="integrations"] .topo-header h1 i`
- `body[data-page="integrations"] .topo-header-actions`
- `body[data-page="integrations"] .topo-detail-icon`

KEEP selectors (at least one independently live class, no splitting):

- `body[data-page="integrations"] .topo-detail-icon.healthy`
- `body[data-page="integrations"] .topo-detail-icon.error`
- `body[data-page="integrations"] .topo-detail-icon.disabled`
- `body[data-page="integrations"] .topo-detail-icon.checking`
- `body[data-page="integrations"] .topo-detail-card[data-service="elasticsearch"] .topo-detail-icon.healthy`
- `body[data-page="integrations"] .topo-detail-card[data-service="kibana"] .topo-detail-icon.healthy`
- `body[data-page="integrations"] .topo-detail-card[data-service="gitlab"] .topo-detail-icon.healthy`
- `body[data-page="integrations"] .topo-detail-card[data-service="opencti"] .topo-detail-icon.healthy`
- `body[data-page="integrations"] .topo-detail-card[data-service="tide"] .topo-detail-icon.healthy`
- `body[data-page="integrations"] .topo-detail-card[data-service="ollama"] .topo-detail-icon.healthy`
- `body[data-page="integrations"] .topo-detail-card[data-service="dfir_iris"] .topo-detail-icon.healthy`
- `body[data-page="integrations"] .flow-pipe-step.active .flow-fork-arm-line, body[data-page="integrations"] .flow-pipe-step.active .flow-fork-stem, body[data-page="integrations"] .flow-pipe-step.active .flow-merge-arm-line, body[data-page="integrations"] .flow-pipe-step.active .flow-merge-stem`

## alerts-page.css

Approve 6 whole rules; retain 13 candidate-touching mixed rules.

Candidates: `ad-sys-card-hdr`, `alerts-filters`, `card-wide`, `hbar-host`, `hbar-rule`, `keyboard-selected`, `list-group`, `mitre-add-row`, `security-banner`, `sortable`, `stats-cases`, `stats-group`, `submenu-arrow`, `timer-icon`.

REMOVE selectors:

- `.stats-group`
- `.stats-cases`
- `.timer-icon`
- `.security-banner`
- `.sortable`
- `.sortable:hover`

KEEP selectors (at least one independently live class, no splitting):

- `.alerts-filters select, .alerts-filters .search-input`
- `.alerts-filters .search-input`
- `.context-menu-submenu .submenu-arrow`
- `.alerts-grid .card-wide`
- `.alerts-grid .card-wide .card-body`
- `.ad-sys-card.mapped .ad-sys-card-hdr::before`
- `.ad-sys-card:not(.mapped) .ad-sys-card-hdr::before`
- `.card-wide .card-body`
- `.side-panel .list-group`
- `.alert-row.keyboard-selected`
- `.mitre-add-row input.mitre-name-input`
- `.hbar-fill.hbar-host`
- `.hbar-fill.hbar-rule`

## discover-page.css

Approve 6 whole rules; retain 1 candidate-touching mixed rules.

Candidates: `field-stats-container`, `indices-container`, `mappings-container`, `saved-search-actions`, `saved-searches-actions`, `saved-searches-container`, `saved-searches-list`, `saved-searches-section`, `search-results-container`.

REMOVE selectors:

- `.search-results-container, .indices-container, .mappings-container, .field-stats-container`
- `.saved-searches-actions`
- `.saved-searches-container`
- `.saved-searches-section h4`
- `.saved-searches-list`
- `.saved-search-actions`

KEEP selectors (at least one independently live class, no splitting):

- `.saved-search-actions .btn`

## settings-page.css

Approve 5 whole rules; retain 0 candidate-touching mixed rules.

Candidates: `env-vars-list`, `sessions-actions`, `settings-layout`, `settings-nav`.

REMOVE selectors:

- `body[data-page="settings"] .settings-layout`
- `body[data-page="settings"] .settings-layout`
- `body[data-page="settings"] .settings-nav`
- `body[data-page="settings"] .env-vars-list`
- `body[data-page="settings"] .sessions-actions`

KEEP selectors (at least one independently live class, no splitting):

- None.

## analytics-page.css

Approve 3 whole rules; retain 6 candidate-touching mixed rules.

Candidates: `analytics-section`, `sys-sev-pill`, `sys-stat-label`, `sys-stat-val`.

REMOVE selectors:

- `.sys-stat-val`
- `.sys-stat-label`
- `.sys-sev-pill`

KEEP selectors (at least one independently live class, no splitting):

- `.analytics-section .section-header`
- `.analytics-section .section-header h2`
- `.sys-sev-pill.crit`
- `.sys-sev-pill.high`
- `.sys-sev-pill.med`
- `.sys-sev-pill.low`

## forensics-page.css

Approve 2 whole rules; retain 0 candidate-touching mixed rules.

Candidates: `editable-title`.

REMOVE selectors:

- `body[data-page="forensics"] .editable-title`
- `body[data-page="forensics"] .editable-title:hover`

KEEP selectors (at least one independently live class, no splitting):

- None.

## playbooks-page.css

Approve 2 whole rules; retain 0 candidate-touching mixed rules.

Candidates: `exec-detail-header`.

REMOVE selectors:

- `.exec-detail-header`
- `.exec-detail-header h3`

KEEP selectors (at least one independently live class, no splitting):

- None.

## Replacement / dynamic inspection

- Threat intel: threat_intel.html:12-39 uses ion-tw-page/layout utilities, heading utilities and input; overview stat fragment uses explicit utility cards. Other ti-* names remain live; only eight exact candidates removed. This corrects last round t-prefix masking, rather than declaring the whole ti-* namespace dead.
- Integrations: integrations.html:395-401 has explicit topology/flow templates. Runtime:855 uses icon class from service;917-926 explicitly builds topo-line/glow/particle and topology-protocol-label;974-981 toggles only status classes;1164-1205 clones flow stage/arrow/branch templates. Branch arms/stems never created. integrations_topology.html uses topo-detail-head/card/status/metrics, no detail icon. New page layout uses utilities. topo-page-wrap is absent as flagged in brief.
- Alerts: timer uses timer-icon-pause at alerts.html:631. Stats/security rows and sortable headers now use utility classes / explicit templates; candidate groups are absent. Mixed selectors retaining live search-input, context-menu-submenu, alerts-grid/card-body, ad-sys-card/mapped, side-panel/alert-row, mitre-name-input and hbar-fill remain intact.
- Discover: discover.html:97-115 uses tools-panel section-panel with flex columns/gap and explicit heading/list utilities; result/index/mapping/field panels use utilities. saved-searches-* IDs are distinct from old classes. Runtime saved-search fragment uses its current explicit button/list classes. Keep saved-search-actions .btn mixed rule.
- Settings: settings.html:25-27 uses grid grid-cols-1 min-[901px]:grid-cols-[220px_1fr] gap-8 mt-6 and flex flex-col gap-1; settings-nav-item is live and unchanged. Env/session lists use utilities and source fragments; old wrapper/action classes absent. Both layout rules (including responsive copy) approved.
- Analytics: analytics.html:137-143 retains sys-stat-card but value/label children explicitly use text/weight/spacing utilities. alerts_systems.html:70 uses ad-sys-sev-pill, not sys-sev-pill. Keep analytics-section with live section-header and severity compound rules with live crit/high/med/low.
- Forensics: forensics.html:205 title directly uses text size, cursor, dashed border and hover utilities; forensics.html:224 still uses editable-desc, unrelated and retained. No runtime editable-title class assignment.
- Playbooks: playbooks.html:102-106 directly applies header layout utilities, keeps exec-detail-panel/body, and fragment uses OOB exec-detail-title ID. No exec-detail-header emission.

## Page gates and browser paths

- /threat-intel: tests/unit/test_ui_fragment_threat_intel.py, tests/unit/test_ui_fragment_threat_intel_actor.py, tests/test_v049_6_threat_intel_recent.py; open overview, actor/search result, campaigns, IOC, reports, watchlist/stories/KEV as available.
- /integrations: tests/unit/test_ui_integrations_topology.py, test_ui_integrations_operations.py, test_ui_integrations_metrics.py, test_ui_integrations_client_templates.py; open topology and process-flow step controls plus details.
- /alerts: tests/unit/test_ui_page_alerts_client_state.py, test_ui_fragment_alerts_queue.py, test_ui_fragment_alerts_systems.py, test_ui_fragment_alerts_detail.py, test_ui_fragment_alerts_cases.py, test_ui_fragment_alerts_playbooks.py, test_ui_fragment_alerts_analytics.py and tests/test_v081_alerts_queue.py; open queue/detail/systems/timer/sorting.
- /discover: tests/unit/test_ui_page_discover_client_state.py, test_ui_fragment_discover_search.py, tests/test_review_20261008_discover_export.py; open saved searches plus result/indices/mappings/field-stat sections.
- /settings: tests/unit/test_ui_settings_integration_styles.py, test_ui_settings_fragments.py, tests/test_settings_page_render.py, test_settings_inventory.py, test_settings_editable.py; open general/session/environment areas, navigation mobile/desktop.
- /analytics: tests/unit/test_ui_fragment_analytics*.py plus tests/test_v080_2_analytics_toggle.py and test_analytics_api_auth.py; open systems tab/stat cards.
- /forensics: tests/unit/test_ui_forensics_overview.py, test_ui_forensics_detail.py, tests/test_forensics_workbench.py, test_forensics_playbook_preview.py; open case/detail summary/title.
- /playbooks: tests/unit/test_ui_fragment_playbooks.py; open catalogue/executions/detail header.

## Broad markup-prefix judgement

Leave the broad standalone quoted-prefix rule this round. The initial suggestion that extracting inline scripts would shrink L-/n_/b_/c- was superseded by the measured probe below: these values come from static JS concatenations, and script separation exposes zero additional dead candidates. Preserve legitimate Jinja macro prefixes such as cl-.

# Cases and mixed-sheet source vetting

Read-only review at base 74d034481588bb55cd02612961fa6395f55c82e0. No application, CSS, or test files edited. Scratch probe css2_cases_probe.py enumerates rule candidates and exact-token boundary references across every HTML/JS/Python source under src/ion (including fragments and non-UI Python).

## Cases: 9 whole-rule removals approved

This is the source reviewer's narrower recommendation, not the final cut list.
The final root decision keeps the entire corrected host-prefix family so scanner
and verifier remain conservative; all 25 cases candidate-touching rules remain.

Original scanner: 17 dead classes, 13 removable rules. Approve these nine whole selectors only:

- .cpanel-alert-item
- .cpanel-alert-toggle
- .cpanel-alert-chevron
- .cpanel-alert-fields
- .cpanel-alert-fields-all
- .cpanel-alert-evidence
- .cpanel-alert-evidence:hover
- .cpanel-alert-extracted
- .cpanel-alert-extracted-title

These classes have no literal source producer anywhere in the whole-source boundary scan. Dynamic construction inspected separately: alert-detail.js has exactly four _cls suffix arguments: fields-table, key, val, showall. Neither those suffixes nor the caller options can produce the approved classes. No Python view model construction supplies them. Current mount uses tabs and explicit sections, with case-only additions in fragments. The old item/accordion/evidence/extracted wrappers no longer mount.

## Genuine live false positive: cpanel-alert-fields-table

cases.html:780 mounts ionAlertDetail with classPrefix:'cpanel-alert' at790. alert-detail.js:73-75 selects that host prefix and joins it with '-' and suffix. _alertFieldsTable at297 emits a table with _cls('fields-table'); _fieldsV2Html at428 does the same. mount:1862 calls render; fields initial/lazy loader:1894 calls loadAlertParsedFields. Thus the two fields-table CSS rules (table and td) style real reachable DOM, for both detail versions. Keep both.

The scanner correction scoped classPrefix harvesting to kind='js', while this actual host config lives inside a script in an HTML template (kind='markup'). Its old kind='all' unit test misses the regression. Root notified to add a markup host-option regression and preserve fields-table.

## Referenced conservative keep: cpanel-alert-showall

_cls('showall') is read in toggleAllAlertFields at680. However the emitted button at327 is fixed alert-parsed-showall, not a _cls call. Retain both cpanel-alert-showall rules conservatively because source refers to the constructed class, but do not report it as a proven emitted DOM class. Fixing the mismatched lookup is outside deletion scope.

## Cases mixed rules: KEEP all 12

- .cpanel-alert-chevron.expanded: includes live expanded modifier; whole-rule policy retains it.
- .cpanel-alert-fields-loading, .cpanel-alert-fields-empty: live empty fragment classes share the rule.
- .cpanel-alert-extracted .caf-key: live caf-key.
- Four .cases-modal-body rules with .form-group or .form-control: retain mixed live names.
- .awx-cfv.mono: live mono.
- .awx-conf .awx-fillb and three tier variants: live awx-fillb.

Even where an absent ancestor proves a compound unmatchable, this tranche preserves mixed rules rather than weakening the approval tool or splitting selectors.

## Five zero-removable sheets: KEEP all

observables-page.css: eight candidate-touching rules. header-actions/badge, observables-filters/search-input, and five context-badge/ctx-* pairings remain. Current related-alert fragment uses context-badge ctx-generic, not dynamic ctx-<context>; the five specific contexts have no producer. Do not split shared rules.

pcap-page.css: six candidate-touching rules. Keep pcap-tab-badge/tone-medium, upload-zone/upload-icon (two), progress outer/inner (two), verdict-info/verdict-confidence. PCAP registry in ui/pcap.py provides fixed tone-high/critical/primary/warning/info values; no medium producer. Current upload/progress/confidence markup uses Tailwind replacements and ID targets. Whole-rule policy preserves mixed live classes.

ion-shell.css: four candidate-touching rules. Keep escaped utility overrides paired with ion-tw-page and bg-grid override. Scanner truncates escaped selector names: border-white is not the full border-white/5 or /10 class, and bg-white is not bg-white/5. The slash-bearing literals are abundant in alerts/observables/base/fragments and are real live utility overrides. bg-ink-950/60 and bg-grid have no literal producer; their mixed rules remain.

chat-page.css: .ai-header-icon.docgen remains mixed. docgen is used as a mode value in chat.html52/442; no ai-header-icon producer is present after utility markup conversion.

arkime-traffic.css: .jvectormap-tip.active remains mixed. Current renderWorldMap at595 instantiates jsVectorMap; vendor bundle uses jvm- classes (including jvm-region), not old jvectormap-tip. Active is live. Do not split/remove this rule.

## Required page checks

Cases removals require opening populated case detail, selecting an alert, then opening Fields for both detailV2 states, including all-fields expansion, guide/process states and copy/pin controls. Check desktop/mobile and light/dark. Run cases panel/core/detail gates plus shared alert-detail tests. Unchanged mixed-only sheets do not require deletion-specific browser comparisons; preserve their files byte-for-byte.

Suggested cases gates: tests/unit/test_ui_cases_panel.py, test_ui_cases_detail_process.py, test_ui_cases_detail_notes.py, test_ui_cases_detail_response.py, test_ui_cases_detail_scope.py, test_ui_cases_alert_guide.py, test_ui_cases_annotation_form.py, test_ui_cases_attack_path.py, test_ui_cases_workbench_playbooks.py, test_ui_fragment_cases.py, test_ui_fragment_cases_observables.py, test_ui_fragment_cases_similar.py, test_ui_fragment_cases_timeline.py, test_ui_fragment_alerts_cases.py. Global source/proof/CSS gates remain required by brief.

## Broad markup prefix judgement

Do not tighten the broad quoted-separator pattern in this removal tranche. Extracting inline script blocks before language dispatch is a reasonable future scanner change, but it needs positive Jinja macro/argument controls and JS inline host-config controls. Otherwise language scoping can again delete real constructed styles. The already demonstrated host-option regression is more consequential than keeping a few extra L-/n_/b_/c- families.

# Round-two prefix judgment (read-only probe)

The markup-prefix narrowing has **zero removal return on this base**. Keep the broad fallback for now. Fix the separate inline-JavaScript `classPrefix` gap before vetting cases rules.

## Method and measurements

`.audit/prefix_probe.py` reads the actual source corpus, extracts `<script ...>...</script>` blocks into a JS corpus for an alternative calculation, and leaves remaining HTML/Jinja in markup. It compares prefix sets and default (all-dead) removable rules across every scanner sheet. CSS comes from `git show 74d03448:<path>` so concurrent removals cannot bias the comparison. No source/scanner/CSS files were edited.

- Existing language-aware scanner: 220 prefixes.
- Script-separated experiment: 221 prefixes.
- Lost prefixes: **none**.
- Newly dead candidate classes: **none**.
- Added prefix: **`cpanel-alert-`**.
- Every standalone separator-ending string extracted from inline scripts is already caught by another JS construction pattern; the broad markup rule adds no unique inline prefix here.
- Broad strings in remaining markup are `alert-`, `badge-`, `bulk-case-`, `case-`, `cl-`, `cmt-`. The `cl-` case is genuinely needed: `_fragments/analytics_case_metrics.html:47` calls `sp.share_bars(..., 'cl-')`, and `analytics_spark.html:54` emits `{{ prefix }}{{ s.key }}`. A literal class or immediate interpolation-prefix scan cannot connect those two strings.

The brief's examples are not inline-markup artifacts in the current corpus: `L-`, `n_`, `b_`, `c-` are absent from the markup prefix set and present in the **static JS** prefix set. The concatenation scanner collects them in `mermaid.min.js` (L-, n_, b_, c-) and `cytoscape.min.js` (c-), for example `"L-" + b.start`, `"n_" + e.a`, `"b_" + fw(this)`, and `S["c-" + e + "-" + t]`. Separating HTML script blocks cannot remove these. Some are generated graph IDs/map keys rather than CSS classes, but changing their recognition has no measured benefit here and needs a different judgment from the broad markup fallback.

Full machine evidence: `.audit/prefix-probe.json` (including concrete source sites and contexts).

## Actual LIVE gap

`templates/cases.html:790` passes `classPrefix: 'cpanel-alert'` to `window.ionAlertDetail.mount`. `static/js/alert-detail.js:73-75` builds each class as `p + '-' + suffix`. Its field rendering explicitly emits `_cls('fields-table')` at lines297/428 and `_cls('key')`/`_cls('val')` at299/437; show-all behavior refers to `_cls('showall')` at680.

`constructed_prefixes` limits the option-pattern matcher to `kind='js'`, but `corpus_by_kind` currently calls all `.html` files markup including inline scripts. Therefore the option producer is missed and `cpanel-alert-fields-table` is reported dead despite a real runtime producer. The split-script experiment adds this family, reduces cases-page default removals from13 to0, and conservatively rescues11 candidate classes (the entire cpanel-alert candidate family). This is not proof that all11 suffixes still render; field-table is definitely live, and the others require the existing per-rule vetting. Keep the family unless explicit suffix proof supports a narrower deletion.

Smallest safe fix: apply the JS option patterns to actual inline script bodies as well. A shared per-kind prefix collector used by scanner and proof checker prevents disagreement. Full parser architecture is unnecessary; do not weaken the conservative markup fallback merely to accomplish this positive-recognition fix. Add a regression with HTML `<script>mount({classPrefix: 'host-detail'})</script>` and CSS host-detail-fields-table, plus the Jinja macro argument `cl-` retention control. A script-aware corpus split must keep literal scanning over the complete original corpus and handle non-JS script types conservatively.

## Proof-checker mismatch

`tools/check_dead_css_vetting.py:62-63` still calls `corpus()` then `constructed_prefixes(text)` with default kind='all', unlike the language-aware CLI. That reintroduces modulo/Python-fstring false prefixes when checking approved removals. This can falsely reject the new ti-* removals because vendored `t%s==0` supplies prefix t.

Smallest fix: import `corpus_by_kind`, join its chunks for literal scanning, and union `constructed_prefixes(chunk, kind=kind)` for each group, exactly as CLI. If a shared collector is introduced for inline-script handling, call it from both. Update the existing `reviewed_sheet` tests to patch corpus_by_kind instead of corpus. Regression: an approved `.ti-obsolete` removal with JS `for(s=1;s<i;s++)t%s==0` must pass; real Python `"ti-%s" % key` must still reject the same removal as constructed. This catches the actual divergence without a broad framework or tests that mirror implementation.



---

# Post-macro correction review

The previous final review missed the live `sys-sev-pill` producer and its unconditional safety verdict was wrong. Browser evidence identified `sev_pills(s.pills, 'sys-sev', ...)` rendering `class="{{ prefix }}-pill"`. The restored base rule is now KEEP. This review supersedes that verdict.

## Current proof

- Independently executed the corrected proof checker: **62 individual whole-rule removals**; all other reviewed source-sheet content preserved.
- Independently counted the current manifest: **157 records, 62 REMOVE, 95 KEEP**. Original candidate list remains 112 classes.
- Ran scanner, sheet-coverage and proof tests with a unique ignored basetemp and random ordering disabled: **35 passed**, no skips.
- Inspected actual macro dynamic class expressions across every template using Jinja ASTs, not only scanner output. The suffix-parameter producer is `analytics_system.html`'s `sev_pills`; its instantiated families are `sev-` and `sys-sev-`. No remaining removed class belongs to those families.
- Other macro dynamic class sites use fixed literal prefixes (donut, severity, PCAP, etc.), directly passed literal classes, conditionals, or existing view-model class values. `share_bars` uses consecutive prefix/key expressions and its literal `cl-` argument remains protected by the broad separator-ending fallback. No additional removed rule was found reachable through a macro class producer in the current source.

## Helper assessment

`macro_class_prefixes` correctly follows literal positional arguments, keyword arguments and defaults for the observed bare parameter followed by a literal hyphen/underscore class suffix. Qualified calls use the macro attribute name, so the actual imported namespace calls are covered. Matching is restricted to class attributes rather than arbitrary prose. Cross-template same-name collisions can add conservative retention; they do not remove a discovered family. Parse failures stop scanning rather than silently treating unknown source as absent.

This is a partial resolver, not a general proof that a macro cannot generate a class: renamed imports, transformed/filtered prefix expressions, runtime arguments, argument forwarding and nonliteral separators are not resolved by this helper. The current source inspection found no such unresolved producer reaching a remaining removed rule. Future scanner use still requires per-rule source and browser verification.

No source edits made; only this ignored review artifact written. Full-suite and browser runs are outside this review's completed evidence; no completion claim is made for them.


---

# Round-two CSS browser comparison

Baseline: `74d034481588bb55cd02612961fa6395f55c82e0`.
Worktree: `C:/Users/lyndo/.codex/worktrees/dead-css-round-two/ION`.

The real application pages are opened at 1440 by 1000 in dark and light
themes. The matrix contains 82 page-state/theme pairs and 164 navigations.
Each baseline CSS response is the exact corresponding `git show` content,
including baseline `ion.css`. Each current response is the worktree file.
Browser interception supplies `Cache-Control: no-store`, bypassing the
unchanged version URL. Baseline UI fragment responses are replayed for the
current sample so changing server metrics do not masquerade as CSS changes.
Browser Date is fixed; finite transitions finish and infinite animations
pause at zero, followed by two animation frames for paint settling.

Final result: **82/82 pairs match** in element counts, the selected computed
properties and rounded width/height, and exact full-page screenshot pixels.
All 164 document navigations returned HTTP 200, with zero uncaught page
errors and zero failed requests. All 35 current stylesheet raw SHA-256
values are unchanged throughout the final run and still match on completion.

## Coverage

- All eight changed page sheets: `/threat-intel`, `/integrations`, `/alerts`,
  `/discover`, `/settings`, `/analytics`, `/forensics`, `/playbooks`.
- Shared-build controls: `/about` gallery and actual presenter overlay,
  `/daily-standup/slides` title and keyboard-selected critical-alert slide,
  `/cases`, `/pcap`, `/chat`, `/observables`, `/arkime-traffic`, `/templates`.
- Threat Intel actors, campaigns, IOC feed, reports, watchlist, stories,
  and KEV tabs.
- Analytics rule noise, case metrics and systems; settings database,
  system, logs and sessions; observables import, graph, patterns and
  watchlist; Discover indices and IOC hunt; integrations topology;
  playbook creation modal.
- The shared alert detail API mounts actual `cpanel-alert-fields-table`
  markup on the cases page with controlled raw input. The analytics source
  handler fixture generates actual `ns-windows` and constructed `ns-p1`
  cards through the real view model and fragment.
- The standup checks handler runs against the private SQLite snapshot and
  disabled default integrations. Its critical slide contains the explicit
  Elasticsearch-not-configured fallback banner, measured count 1 and one
  actual snapshot row; no synthetic critical-alert HTML is inserted.

## Regression caught and corrected

The first full pass caught a live rule wrongly proposed for removal:
`.sys-sev-pill`. `analytics_system.html` calls its Jinja macro with
`'sys-sev'`, and the macro emits `{{ prefix }}-pill`. The actual systems
cards lost the base rule's flex layout, font and padding. Both themes had
15 differing element records and a four-pixel card-height increase.

The parent restored the rule and added scanner/proof coverage. The final
entire matrix repeats against the restored CSS. Original evidence remains
in `css2-browser-first-pass-results.json`, its log, and the retained
first-pass analytics screenshots. Browser checks were necessary: the
otherwise-green source gates did not exercise this constructed markup.

## Pixel-level qualification

Earlier passes observed a tiny difference at the dark About gallery's
Present button: four antialiased corner pixels differed by one RGB channel
level at most, within bounds `(1276,356)-(1279,358)`. Every computed property
on that button was identical, along with the document's sampled properties
and geometry. A focused repeat after two paint frames retained the
difference; baseline-versus-baseline control was pixel-identical in all
four About states. The final entire-matrix repeat is pixel-identical for
this pair too. The earlier raw records are retained in first-pass,
paint-control, button-control and baseline-control result files. No pixels
are masked and no application change was made for this observation; its
precise rendering cause is unproven.

## Evidence and limits

`css2-browser-summary.json` is generated by `css2-browser-summarize.py`.
It asserts all final element counts and the selected computed properties
and rounded width/height match, all document navigations return 200, no
uncaught page errors occur, and every final CSS raw SHA-256 still matches
the final run's starting bytes. It checks the four-pixel exception against
the actual screenshot bytes and complete button computed-property maps.
Raw navigation records, console messages, failed requests, baseline CSS
hashes, and per-state screenshots remain under the `css2-browser-*` names.

The fixture asserts imports resolve to this worktree, uses SQLite backup
into a private data directory, overrides authentication, disables startup
lifespan side effects, and uses secret-free default configuration. It does
not load real integration configuration or change `.env`/`config.json`.
Browser API reads are controlled empty responses; UI fragments otherwise
use the private snapshot and disabled integrations. EventSource MIME-type
messages, if present in the final summary, are caused by controlled empty
API responses and apply to both CSS modes. The final 12 console messages
are all this controlled EventSource MIME-type warning. No CSP violations
or other console errors are recorded in the final selected samples.

These checks prove parity for the opened desktop states. They do not claim
live provider results, login/session lifecycle, mobile layout, every popup,
or populated PCAP/IKE/TI/Arkime-analysis coverage. The real PCAP upload shell
is opened; no capture is fabricated, uploaded or analyzed. No integration
mutation controls are exercised.

Fixture PID 105676 was verified by command line before stopping. Port 8836
has no remaining listener; the final raw-hash summary was generated and
passed before shutdown.
