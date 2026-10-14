# Read-only CSS vetting: five page sheets

Base inspected: `9edf38f9`. No source or stylesheet edited by this worker.
Initial scanner results: cases 74 candidates/95 removable rules; alerts
64/73; chat 43/62; integrations 26/39; forensics 18/23. These are baseline
counts, not an authorization to use the scanner's full dead set.

## Proof method and dynamic construction

`.audit/vet_a_probe.py` boundary-searched every candidate against every
`.html`, `.js`, and `.py` below `src/ion`, including all fragments and all
Python producers (not only `web/ui`). `.audit/vet-a-probe.txt` records the
result. Only `cmdline` had literal hits; those hits are KB prose, process
paths and SQL/Volatility commands, not class producers. No candidate has
a literal markup/JS/Python producer in this tree.

That negative result alone was insufficient: inspection of all nonvendor
lone joiners exposed a real hidden producer in `static/js/alert-detail.js`.
The other nonvendor joiners are process-map keys (`cases.html:952`), panel
layout keys (`cases.html:1427`), annotation element IDs (`cases.html:2278`),
chat message IDs (`chat.html:654`), dates (`daily_work.html:51`), and
security dashboard badge kinds (`security_dashboard.py:212`, severity/status,
not candidates in these sheets). Vendor joiners are chart/time/vis internals;
host inputs do not supply any candidate family to their class names.

### LIVE false positive: keep `cpanel-alert-fields-table`

`cases.html:790` passes `classPrefix: 'cpanel-alert'` into the shared component.
`alert-detail.js:73-79` has this real generator:

```javascript
function _cls(suffix) {
  var p = _opts.classPrefix || 'alert-parsed';
  if (suffix === 'fields-table') return p + '-fields-table';
  if (suffix === 'key') return p === 'alert-parsed' ? 'apf-key' : 'caf-key';
  if (suffix === 'val') return p === 'alert-parsed' ? 'apf-val' : 'caf-val';
  if (suffix === 'showall') return p + '-showall';
  return p + '-' + suffix;
}
```

The raw-field table (`alert-detail.js:297`) and parsed table (`:428`) both
emit `_cls('fields-table')` into their class attribute. Deleting this rule
would unstyle live case-detail tables. Teach the scanner this option-selected
prefix construction and regression-test the actual snippet plus host option.
The simple literal-prefix scanner cannot infer `p` from its host caller.

### KEEP conservatively: `cpanel-alert-showall`

`alert-detail.js:680` calls `classList.contains(_cls('showall'))` when adapting
the all-fields action. This is a real runtime class reference even though no
current emitter for that exact class was found. Preserve it rather than
declaring a queried adapter class removable. The prefix fix may deliberately
keep further cpanel-alert classes; that is conservative scanner behavior,
not proof that those further classes are live.

## cases-page.css

DEAD (72 exact candidates; remove only complete rules containing
these and satisfying the non-strict all-dead policy):

- analytics-card, analytics-card-accent-blue, analytics-card-accent-danger,
  analytics-card-accent-info, analytics-card-accent-purple,
  analytics-card-accent-success, analytics-card-accent-warning,
  analytics-card-full, analytics-grid, analytics-row-donuts,
  analytics-summary-strip.
- attn-banner-dismiss, autoinv-report-wrap.
- awx-bd, awx-bl, awx-bob, awx-cf, awx-cfk, awx-cfv, awx-common, awx-conf,
  awx-escbadge, awx-lab, awx-note, awx-obs, awx-obscount, awx-pctv, awx-tier,
  awx-track, awx-verdict, cmdline, tier-high, tier-low, tier-medium,
  v-benign_true_positive, v-duplicate, v-false_positive, v-insufficient_data,
  v-not_applicable, v-true_positive.
- cases-board-toolbar, cases-filter-input, cases-filter-select,
  cases-filters-bar, cases-loadmore-btn, cases-loadmore-note, cases-modal,
  cases-modal-body, cases-modal-close, cases-modal-footer, cases-modal-header,
  cases-showing, cases-subtitle, cases-toolbar-field, cases-toolbar-spring.
- closure-ai-btn, closure-legend, closure-legend-dot, closure-legend-item,
  closure-notes-label-row, closure-stacked, closure-stacked-seg.
- cpanel-alert-chevron, cpanel-alert-evidence, cpanel-alert-extracted,
  cpanel-alert-extracted-title, cpanel-alert-fields, cpanel-alert-fields-all,
  cpanel-alert-fields-loading, cpanel-alert-item, cpanel-alert-toggle,
  cpanel-proc-toggle.

All 72 have the whole-tree absence proof above and no recoverable or unknown
class constructor feeding these names. Important stronger historical proof:
`git show b9f0ae17 -- src/ion/web/templates/cases.html` deletes `_cfRow`,
`_alertWidgetExtras`, and `_obsChipHtml`. `_cfRow` emitted awx-cf/cfk/cfv and
cmdline; `_alertWidgetExtras` emitted awx-common/lab/obs/obscount, escalation,
Bob/confidence/verdict classes, `tier-` and `v-` dynamic families. The current
server `cases_panel.html` emits the still-live awx-obschip/ot/tl/td/obsrow
families. Those retained families must not be swept up by `awx-*` grouping.
`awx-fillb` still has a JS selector reference and stays too.

Panel markup is `cases_panel.html`, board markup is `cases_board.html`, and
closure markup is the closure modal and inert AI button templates within
`cases.html`, with closure summary rows in `cases_summary.html`.
Their current classes and view-model allowlists in `ui/cases.py` were
inspected; none generates the 72 names. `PANEL_STATUS_CLASSES`, severity,
age and closure color mapping feed different retained names.

Gates: test_ui_cases_panel.py, test_ui_fragment_cases.py,
test_ui_fragment_cases_similar.py, test_ui_cases_board_scope.py,
test_ui_cases_annotation_form.py; additionally all test_ui_cases_detail_*.py
and test_ui_cases_alert_guide.py exercise the live shared detail table/guide.

## alerts-page.css

DEAD (all 64): acp-close, acp-closure-body, acp-closure-close,
acp-closure-footer, acp-closure-header, acp-closure-modal, acp-header,
ad-card, ad-card-header, ad-card-hint, ad-card-icon, ad-metric,
ad-metric-label, ad-metrics-strip, ad-overview-bottom, ad-overview-grid,
ad-sys-card-alerts, ad-sys-card-body, ad-sys-card-hdr, ad-sys-card-name,
ad-sys-header, ad-sys-sev-row, ad-sys-stat, ad-sys-stat-lbl, ad-sys-stat-val,
ad-sys-unmapped, ad-tabs, ai-generate-row, ai-hint, alerts-filters,
bulk-actions-buttons, bulk-actions-info, bulk-select, bulk-separator,
card-wide, chart-axis, chart-container, chart-container-sm, chart-grid,
chart-label, context-icon, context-menu-divider, context-menu-item,
custom-time-input, custom-time-sep, filter-separator, globe-container,
hbar-host, hbar-rule, keyboard-selected, list-group, mitre-add-row,
mitre-heatmap, mitre-heatmap-card, mitre-techniques-list, ns-icon,
pattern-dismiss-btn, pattern-panel-title, security-banner, sortable,
stats-cases, stats-group, submenu-arrow, timer-icon.

Whole-tree absence proof includes `ui/alerts.py` and current alert fragments.
Shared `_cls` above uses alert-parsed on the alerts host; it emits none of
these candidate classes. Current queue construction is aq-*; classes from
static conditionals and severity prefix are already retained by the scanner.
The current chart/system fragments use distinct retained classes; no
ad-sys candidate constructor is present. Legacy generic names such as
list-group/sortable also have zero references elsewhere in src/ion.

Gates: test_ui_page_alerts_client_state.py and all
test_ui_fragment_alerts_*.py, plus test_ui_routes_answer_json.py.

## chat-page.css

DEAD (all 43): ai-brand-sub, ai-brand-text, ai-brand-title,
ai-chat-container, ai-chat-page, ai-chat-sidebar, ai-check, ai-collapsible,
ai-context-grid, ai-header-icon, ai-header-left, ai-icon-btn, ai-input-area,
ai-input-form, ai-input-meta, ai-input-row, ai-main, ai-main-header,
ai-mode-tabs, ai-model-footer, ai-quick-list, ai-section, ai-section-label,
ai-settings-divider, ai-settings-row, ai-sidebar-brand, ai-upload-area,
ai-wcard-icon, ai-wcard-text, ai-welcome-cards, btn-gen-save,
docgen-actions, docgen-body, docgen-form-area, docgen-label, docgen-opt,
docgen-options, docgen-preview-actions, docgen-preview-header,
docgen-section, docgen-template-grid, docgen-templates, docgen-textarea.

The literal whole-tree proof covers chat fragments and Python chat citation
allowlists; its only variable class assignment adds role (user/assistant),
feedback classes and icon names, not these families. `git log -S ai-brand-sub`
shows e3389827 restyling chat onto daisyUI before a170edcd moved the unused
CSS out. The present chat template uses explicit utilities for those layout,
brand, form and document-generator wrappers; it does not reconstruct names.

Gates: test_ui_fragment_chat_files.py, test_ui_fragment_chat_answer.py,
test_ui_chat_stream_floor.py, test_ui_chat_markdown_render.py.

## integrations-page.css

DEAD (all 26): copy-field, dashboard-layout, dashboard-main,
dashboard-sidebar, filter-controls, flow-fork-arm, flow-fork-arm-arrow,
flow-fork-arm-line, flow-fork-bar, flow-fork-stem, flow-fork-zone,
flow-merge-arm, flow-merge-arm-line, flow-merge-arrow, flow-merge-bar,
flow-merge-stem, flow-merge-zone, flow-row, flow-section-subtitle,
metrics-card, metrics-card-wide, topo-detail-icon, topo-header,
topo-header-actions, topo-page, topo-page-wrap.

Whole-tree absence proof includes integrations Python producers and all
fragments. `createFlowSlide` at integrations.html:1162 clones named templates,
adds flow-pipe-step/decision/branch and active/visible/entering/hidden, then
sets colors and icons. It uses horizontal arrow and branch templates; it
does not emit the old fork/merge geometry families. Topology variable classes
are connected/disconnected/error and explicit health allowlists, not topo-*
candidate classes. `test_route_audit_phase7e_topology.py` explicitly proves
topo-page-wrap was only ever a CSS selector (870b3219 moved it); it was
never markup. `git log -S flow-fork-zone` locates the old merged topology
flow layout in 34092c61 and stylesheet extraction in 870b3219.

Gates: test_ui_integrations_topology.py, test_ui_integrations_operations.py,
test_ui_integrations_metrics.py, test_ui_integrations_client_templates.py,
test_ui_fragment_network_topology.py, test_route_audit_phase7e_topology.py,
test_v098_topology_edges.py, test_v088_topology.py.

## forensics-page.css

DEAD (all 18): cases-filter-input, cases-filter-select, cases-filters-bar,
editable-title, fr-ref-grid, fr-stage-analysis, fr-stage-evidence,
fr-stage-intake, fr-tile, fr-tile-amber, fr-tile-blue, fr-tile-cyan,
fr-tile-green, fr-tile-label, fr-tile-purple, fr-tile-red, fr-tile-value,
fr-tiles.

Whole-tree proof includes forensics producers, fragments and all templates.
The current intake/evidence/analysis headers at forensics.html:66-75 use
explicit utility classes. Reporting/review/closed keep named styles; do not
generalize the dead three into the whole fr-stage family. Current counters
use explicit utility wrappers rather than fr-tile family; reference docs
also use utilities instead of fr-ref-grid. Current classList writers add
active/open/dragover/toast states only. `git log -S fr-tile-blue` locates
the old layout at fe5e922f, replacement in e3e28068, extraction 1258d2cf.

Gates: test_ui_forensics_overview.py, test_ui_forensics_detail.py.

## Mixed selector and rule policy

Keep every selector branch that pairs a proven dead class with any class
outside the approved dead set. Do not use strict. Examples deliberately kept:
`.awx-conf .awx-fillb.tier-high/medium/low` (awx-fillb live),
integrations `.flow-pipe-step.active .flow-fork-arm-line` and matching
fork/merge stem/arm rules (flow-pipe-step/active live), and any forensics
`.modal...`/other live ancestor pairing. Keep every mixed comma rule intact.
No selector branches are split in this tranche. Do not delete an entire
rule just because one branch is dead.

Final per-sheet removal counts must be measured after the parent scanner
fix and vetted manifest are applied. Browser opening is the parent's gate;
this worker performed source review only and makes no visual claim.
# CSS vetting: pages B (read-only source review)

Base: main release 9edf38f9. No application source or CSS edited by this reviewer.
Reviewed brief, scanner and its regression tests before examining candidates.
The initial lists below are the release scanner's worklist, before the root
agent's Python-corpus / formatted-prefix / macro-prefix improvements.

## Evidence and deletion policy

Exact boundary search covered every .py, .html and .js under src/ion, including
all fragments and vendored JS. The probe is .audit/vet-pages-b-probe.py. The
root inventory independently records exact source references. An empty exact
search was not treated as enough: reviewed relevant view-model producers,
template macros and classList/className writers, plus the application's lone
hyphen joiners. Those joiners construct IDs, dates or alert-detail's own prefix
family, not any of the deletion families below. Read each page's current shell
and relevant fragment families: former wrappers now use Tailwind/daisyUI or
the retained newer page classes.

Only whole rules with entirely proved-absent positive classes are approved.
Do not use --strict. Keep mixed selectors and mixed comma lists intact. For
example, retain the whole observables-filters/select/search-input rule and the
whole discover search-results/indices/mappings/field-stats-container rule.
The latter's search-results-container branch is conservatively retained by
the improved scanner. An absent candidate in a compound with a live class is
explicitly KEEP below, even when the compound could logically be unreachable.

## analytics-page.css: 42 initial candidates

LIVE; retain:

- fp-high, fp-med, fp-low: analytics.py fp_band returns these exact strings
  (lines 368-371). analytics_rule_noise.html consumes the band in markup.
- ns-windows, ns-linux, ns-network, ns-aws, ns-azure, ns-gcp, ns-endpoint,
  ns-mail, ns-dns, ns-web, ns-auth: NAMESPACE_KINDS at analytics.py:994-1006,
  namespace_kind returns each lookup result. analytics systems cards consume
  the class. Removing these loses namespace colours.
- ns-p0, ns-p1, ns-p2, ns-p3, ns-p4, ns-p5, ns-p6, ns-p7, ns-p8, ns-p9,
  ns-p10, ns-p11: analytics.py:1035 returns
  `"ns-p%d" % (digest[0] % NAMESPACE_FALLBACKS)` with NAMESPACE_FALLBACKS=12.
  This is real percent-format construction, requiring scanner regression.
- cl-benign_true_positive, cl-duplicate, cl-false_positive,
  cl-insufficient_data, cl-not_applicable, cl-true_positive, cl-unspecified:
  analytics_case_metrics.html:47 calls
  `sp.share_bars(closure_reasons, 'Closure Reasons', 'cl-')`;
  analytics_spark.html:54 renders
  `class="closure-bar-fill {{ prefix }}{{ s.key }}"`.
  shares() passes closure mapping keys through entity_kind(), which accepts
  safe underscores. No literal complete class is needed in either source.

ABSENT and whole-rule deletion approved: analytics-grid, analytics-stats-bar,
astat-label, astat-value, idx-sev-pills. Nine whole rules in improved inventory.
Current analytics.html uses grid utilities and text/font utilities for these
areas; namespace cards and charts use retained sys-* classes.

ABSENT but KEEP: analytics-section (paired with live section-header),
sys-sev-pill, sys-stat-label, sys-stat-val (improved scanner conservatively
retains the sys-* family). No safe deletion claim is made for these retained
rules. All these exact names have no source emitter outside CSS.

Gates: tests/unit/test_ui_fragment_analytics.py and
test_ui_fragment_analytics_{cards,dashboard,metrics,panels,system}.py.
Browser: /analytics; overview, rule noise, case metrics, systems, light/dark.

## settings-page.css: 11 initial candidates

ABSENT, whole-rule deletion approved: cleanup-form, db-actions, db-section,
info-grid, logs-toolbar, nav-divider, nav-icon. Eleven whole rules.
Settings shell uses grid utilities (settings.html:25), nav uses flex classes,
divider uses h-px/bg-base-300, icon span uses mr-1. Current settings fragment
families and Python models emit none of these old classes.

ABSENT but conservatively KEEP: env-vars-list, sessions-actions,
settings-layout, settings-nav. The improved scanner retains broader env-*,
sessions-* and settings-* families. This is conservative retention, not a
claim that the exact old wrappers are rendered. settings-nav-item is LIVE
(settings.html:28 onwards and JS selectors) and must survive.

Gates: test_ui_settings_fragments.py, test_ui_settings_integration_styles.py.
Browser: /settings; database, system, logs, sessions and navigation sections.
Do not expose secret values while verifying settings.

## observables-page.css: 16 initial candidates

ABSENT, whole-rule deletion approved: graph-controls, graph-legend,
import-example, import-tabs, legend-dot, legend-item, observables-filters,
patterns-controls, patterns-desc, watchlist-alert-icon. Fourteen whole rules.
Reviewed observables.html graph/import/pattern modal controls and
observables.py plus _fragments/observables_*; no matching class producer.
Their current controls use utility classes and retained current widgets.

ABSENT but KEEP mixed compounds: ctx-dest, ctx-host, ctx-source, ctx-subject,
ctx-target (paired with LIVE context-badge), header-actions (badge descendant).
observables_detail.html emits ctx-generic unconditionally for an available
context; it does not build ctx- plus an arbitrary context. ctx-generic stays.
Keep entire comma rule `.observables-filters select, .observables-filters
.search-input`, including its first absent-only branch; do not split it.

Gates: test_ui_observables_core.py, test_ui_observables_analysis.py,
test_ui_observable_forensic_shell_permissions.py.
Browser: /observables; import, graph, patterns, watchlist, detail context.

## threat-intel.css: 8 initial candidates

Exact names ABSENT: ti-header, ti-page, ti-search-bar, ti-search-input,
ti-stat-card, ti-stat-label, ti-stat-value, ti-stats. All are KEEP because the
improved scanner conservatively retains the ti-* family; no change proposed
to this sheet. Current threat_intel.html header/stats/search use utilities;
Python threat_intel.py and all threat_intel_* fragments do not emit these
exact old wrappers. The many current ti-* classes remain live.

Gates if changed later: test_ui_fragment_threat_intel.py,
test_ui_fragment_threat_intel_actor.py. No page cut in this tranche.

## playbooks-page.css: 6 initial candidates

ABSENT, whole-rule deletion approved: checkbox-group, filter-controls,
form-section, header-actions, page-header. Seven whole rules. Current shell
playbooks.html:13 uses utility header, library controls at :38 use flex
utilities; create modal sections use current classes. playbooks.py and its
library/step/detail fragments contain no construction of these wrappers.

ABSENT but KEEP: exec-detail-header (conservative exec-* family retention).

Gates: test_ui_fragment_playbooks.py and test_ui_cases_workbench_playbooks.py.
Browser: /playbooks; library, create modal, execution detail.

## discover-page.css: 13 initial candidates

ABSENT, whole-rule deletion approved: bulk-ioc-form, discover-search-form,
ioc-hunt-form, page-subtitle. Two whole rules; one groups the three forms.
Current discover.html forms/header have utility classes; discover.py emits
result rows and state classes, not old form wrappers.

ABSENT but KEEP: field-stats-container, indices-container, mappings-container
(their comma list includes conservatively retained search-results-container);
saved-search-actions, saved-searches-actions, saved-searches-container,
saved-searches-list, saved-searches-section, search-results-container
(conservatively retained saved-search-/search-results- families). Current
discover_saved_searches.html emits saved-search-info etc but not these exact
old wrapper names. Keep the entire shared container rule; no selector split.

Gates: test_ui_fragment_discover_search.py,
test_ui_page_discover_client_state.py. Browser: /discover; search, single IOC,
bulk IOC, saved searches, indices, mappings, field stats.

## pcap-page.css: 17 initial candidates

LIVE; retain: tcp, udp, icmp (pcap.py PROTOCOL_CLASSES at :81-83;
pcap_network fragment consumes mapped protocol class), no-response
(IKE_STATUS_CLASSES at :823-828, pcap_detail fragment), tone-high,
tone-primary, tone-warning (pcap.py table metadata at :519 onwards),
pcap-ti-chip and pcap-ti-link (pcap.py TI_CHIP_CLASS/TI_LINK_CLASS :1268-1269,
passed into threat-intelligence fragment). These Python classes were absent
from the original scanner corpus.

ABSENT, whole-rule deletion approved: findings-widget-head, pcap-page,
pcap-reset, verdict-info. Five whole rules. pcap-page matches a CSS filename
and comment, not a class; pcap.html uses ion-tw-page/max-w utilities.
Findings header, reset button and summary information use current utilities.

ABSENT but KEEP mixed compounds: progress-bar-inner, progress-bar-outer,
upload-icon, tone-medium. Retain verdict-info .verdict-confidence too (the
confidence name is counted live). Current progress markup uses h-1.5/h-full
utilities and IDs, upload icon uses utility wrapper, table tone enum has no
tone-medium entry. Do not delete compound rules under a strict policy.

Gates: test_ui_fragment_pcap_{detail,findings,summary,tables}.py,
test_pcap_ti_findings.py, test_pcap_auto_ti_annotation.py.
Browser: /pcap with real capture only; summary/protocol bars, findings/TI,
IKE detail where real capture carries it. No synthetic capture.

## arkime-traffic.css: 3 initial candidates

ABSENT, whole-rule deletion approved: jvectormap-tip, jvectormap-zoomin,
jvectormap-zoomout. Two whole rules. Important vendor check: the shipped
static/js/jsvectormap.min.js emits jvm-tooltip, jvm-zoom-btn, jvm-zoomin and
jvm-zoomout, NOT jvectormap-*; arkime_traffic.html loads precisely this file
at :333. There is no external jQuery vector map script producing the old
names. KEEP `.jvectormap-tip.active` because active is live (mixed policy).

Gate: test_ui_fragment_arkime_traffic.py. Browser: /arkime-traffic (verified
server.py page registry); map tooltip/zoom and exclusions, light/dark.

## templates-page.css: 2 initial candidates

ABSENT, whole-rule deletion approved: card-description, folder-manage-path.
Two whole rules. Reviewed templates.html plus templates_page_* fragments and
templates_page.py: list cards and folder management path use utilities / the
current fragment classes, not these old names. No prefix builder recreates
either candidate.

Gates: test_ui_fragment_templates_page.py, test_ui_fragment_template_form.py,
test_ui_fragment_template_render.py. Browser: /templates list/folder manager.

## ion-shell.css: 4 initial candidates; unchanged

KEEP all: bg-grid, bg-ink-950, bg-white, border-white. Zero whole deletions.
bg-ink-950, bg-white and border-white are class-parser artefacts: CSS actually
escapes slashes in bg-ink-950/60, bg-white/5, border-white/5 and border-white/10;
the scanner names only the leading identifier. Real templates carry the
slash variants (e.g. alerts.html, observables.html, base.html). bg-grid is
absent but paired with live ion-tw-page in its light-theme selector.
Never use --strict on this sheet. Light-theme shell gates and browser checks
on changed pages cover retained overrides; no cut proposed.

## Reviewer hand-back

Approved whole deletions after root scanner fixes: analytics 9, settings 11,
observables 14, playbooks 7, discover 2, pcap 5, arkime 2, templates 2.
Threat-intel and ion-shell unchanged. Total 52 whole rules. This is a source
vetting recommendation, not a report that root has deleted/tested them.

Root owns execution of per-sheet gates, CSS-current/rebuild, browser checks,
full parallel suite and final actual deletion counts. No tests or browser
runtime were run by this read-only reviewer.
