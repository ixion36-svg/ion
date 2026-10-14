# Dead CSS round two, 2026-10-14

Branch `codex/dead-css-round-two`, exact base
`74d034481588bb55cd02612961fa6395f55c82e0` on `fix/dead-css-vetting`.

The original worklist has 112 candidate classes, 86 whole-rule candidates and
157 candidate-touching rule records. The new manifest records **62 REMOVE and
95 KEEP** decisions. All mixed selectors remain intact. No bulk `--write` or
`--strict` deletion is used.

Of the 57 newly visible whole rules, 43 are removed; 13 cases-family rules and one analytics macro rule
are retained after correcting two live-construction misses. Another 19 previously
reported candidates are removed: five mapped hashes, six simple legacy nav rules
and eight page-input rules. Ten wholly removable candidates deliberately remain
for the hash/negation reasons below.

## Per-sheet decisions

KEEP counts include mixed rules that were never wholly removable.

| Sheet | Remove | Keep | Reason for retaining candidates |
| --- | ---: | ---: | --- |
| cases-page.css | 0 | 25 | Inline host prefix constructs a live fields table; showall is queried. Preserve the family and all mixed rules. |
| threat-intel.css | 12 | 0 | Old wrappers have no source producer; current markup uses utilities. |
| integrations-page.css | 7 | 12 | Mixed flow-active compounds retained. topo-page-wrap is absent from markup, including history. |
| alerts-page.css | 6 | 13 | Mixed header/table compounds retained. |
| discover-page.css | 6 | 1 | Mixed container rule retained as a whole. |
| settings-page.css | 5 | 0 | Current layout, navigation and sessions use utilities. |
| analytics-page.css | 2 | 7 | Live macro-generated sys-sev-pill restored; namespace compounds and section-header pairing retained. |
| forensics-page.css | 2 | 0 | editable-title replaced by current markup utilities. |
| playbooks-page.css | 2 | 0 | Current execution-detail header uses utilities. |
| ion-migrated-styles.css | 5 | 8 | Five verified existing replaced_by claims; eight lack a verified recorded replacement. |
| ion-legacy.css | 6 | 2 | Negated selectors retained under the proof tool's conservative complex-selector policy. |
| ion-pages.css | 9 | 7 | Mixed print selectors and shared compounds retained. |
| observables-page.css | 0 | 8 | Mixed selectors only. |
| pcap-page.css | 0 | 6 | Mixed selectors only. |
| ion-shell.css | 0 | 4 | Mixed selectors and truncated escaped utility names. |
| chat-page.css | 0 | 1 | Mixed selector only. |
| arkime-traffic.css | 0 | 1 | Mixed selector only. |

Every baseline selector, rule hash, class list and decision is in
[the round-two manifest](dead-css-round-two-2026-10-14.json).
The prior round's manifest and hashed map are preserved.

## Scanner before/after

Before is the immutable exact-base report. After uses the corrected detector
and final source sheets. The 14 live-construction candidates disappear from
the report through detection, rather than deletion. Ten conservative candidates
remain: eight unmapped hashes and two negated legacy rules.

| Sheet | Whole candidates before | Whole candidates after |
| --- | ---: | ---: |
| alerts-page.css | 6 | 0 |
| analytics-page.css | 3 | 0 |
| arkime-traffic.css | 0 | 0 |
| cases-page.css | 13 | 0 |
| chat-page.css | 0 | 0 |
| discover-page.css | 6 | 0 |
| forensics-page.css | 2 | 0 |
| integrations-page.css | 7 | 0 |
| ion-legacy.css | 8 | 2 |
| ion-migrated-styles.css | 13 | 8 |
| ion-pages.css | 9 | 0 |
| ion-shell.css | 0 | 0 |
| observables-page.css | 0 | 0 |
| pcap-page.css | 0 | 0 |
| playbooks-page.css | 2 | 0 |
| settings-page.css | 5 | 0 |
| threat-intel.css | 12 | 0 |
| **Total** | **86** | **10** |

## Live candidates and scanner consistency

`cpanel-alert-fields-table` is emitted by `alert-detail.js` through
`_cls('fields-table')` using `classPrefix:'cpanel-alert'` in the cases template's
inline JavaScript. The language-scoping fix recognised host options in `.js`
files but missed this real HTML host. `cpanel-alert-showall` is dynamically
queried, although the currently emitted show-all button has a fixed different
class. The former is demonstrably live; the latter is conservatively retained
as a runtime reference. Other old cpanel-alert suffixes were proved absent,
but remain with the conservatively recognised family. No claim is made that
every retained member is rendered.

The smallest scanner fix lets the host-option pattern inspect markup as well
as JavaScript. It avoids parsing or duplicating script bodies and leaves Python
percent/f-string detection restricted to Python. The report consequently drops
from 86 to 73 candidates before any CSS cut. The proof checker now uses the
same per-language union as the scanner instead of calling the language-blind
`constructed_prefixes(corpus())` default. Two regressions were observed failing
before these fixes; a third control preserves real Python formatting detection.

Browser verification then disproved the initial source-review verdict for
`.sys-sev-pill`. The analytics systems fragment calls
`sev_pills(s.pills, 'sys-sev', s.alert_count)` and its macro emits
`class="{{ prefix }}-pill {{ p.short }}"`. The missing base rule changed flex
layout, font, padding and card height in both themes. Exact-token search and
the original prefix patterns missed this construction. The rule is restored.

The scanner now follows literal positional/keyword/default macro arguments
into a parameter joined to a separator inside a class attribute. Jinja's AST
keeps this narrower than treating arbitrary hyphenated strings as prefixes;
malformed macro markup stops the scan rather than silently losing protection.
A regression using the actual sev_pills shape was observed failing before the
fix. A second test covers keyword/default/qualified calls and excludes prose.
A complete rescan rescued exactly one additional proposed cut, reducing the
original whole-rule candidate count from 73 to 72 before approved cuts. The original
157-record worklist remains intact, with its decision changed to KEEP.
This is a partial resolver: renamed imports, transformed arguments and runtime
forwarding still need manual review. A fresh independent AST inspection of all
macro class sites found no other remaining removed rule reachable that way.

The shell's `bg-white` and `border-white` candidates are truncated parser names
for escaped `/5` and `/10` utility selectors. Their full class names occur in
markup and their rules are preserved.

## Judgment on the broad markup rule

Keep it for this tranche. A read-only experiment separating inline scripts
found zero extra dead classes or removable rules. It preserved all existing
220 prefixes and gained the one legitimate cpanel-alert host prefix. The cited
`L-`, `n_`, `b_` and `c-` values came from static Mermaid/Cytoscape concatenations,
not the current markup-only fallback. Removing that fallback would therefore
not remove those values. The legitimate `'cl-'` macro argument still needs
protection when the macro joins `{{ prefix }}{{ s.key }}`.

Separating inline scripts offered zero additional removals here. Browser
evidence nevertheless justified parsing macro argument flow to protect a live
class. Broad-prefix retention remains conservative; the scanner continues to
require per-rule review and browser checks.

## Root evidence for build inputs and hashes

Exact boundary search of all `.html`, `.js` and `.py` under `src/ion` finds no
producer for the legacy nav or page-input candidates. The only nav-links and
navbar hits are comments. `app.js` records deletion of the old mobile nav
builder. The current base navigation uses different classes. Daily standup
slides and their fragment use utility layouts and named deck-slide/deck-title
classes, not deck-brand-big, deck-h-gap/row or deck-kpi/label/value. Old chat
widget wrappers and print navbar selectors have no current DOM producer.
Six simple legacy nav rules and nine whole page-input rules are approved;
mixed print lists and the two negated nav rules remain.

The five removed hashes have existing replacements verified in both CSS and
actual markup/clones: `_ion-s-5eaab7cb30` becomes `.pb-preview-step`,
`_ion-s-8bc7ebe99c` becomes `.an-dist-track`, and `_ion-s-a55ef5c079`,
`_ion-s-b76ce82a4d`, `_ion-s-e26f061ab9` become `.forensic-progress`.
The playbook preview template, analytics velocity fragment and native progress
element remain. No replacement claim is invented for the remaining eight hashes.

## Verification

The pinned Tailwind binary is present. Page CSS is outside `@source`, but
`frontend/ion-legacy.css` and `frontend/ion-pages.css` are direct `@import` build
inputs. Their cuts therefore require checking and, if stale, regenerating the
compiled `ion.css` even though page-sheet cuts do not change utility discovery.

All eleven edited source sheets passed their page gates plus scanner, coverage,
proof and CSS freshness tests. After the macro correction, analytics reran:
252 passed. Individual successful gate totals were threat intel 329,
integrations 234, alerts 618, Discover 111, settings 121, analytics 252,
forensics 242, playbooks 110, mapped hashes 199, legacy input 55 and page
input 156. These overlap and are not added into a suite total. The two input
freshness checks first failed on stale generated CSS, then passed after the
pinned rebuilds; those failures are retained in the local evidence. Final scanner/coverage/proof/freshness/pinned-build checks: 41 passed.
Scoped Ruff and whitespace checks pass. The final proof verifies 62 exact
whole-rule cuts and preservation of every other reviewed source-sheet byte.
`ui_rewrite_audit.py --check` reports **0 problems**; its baseline, the prior
manifest and hashed map are unchanged. Pinned Tailwind v4.3.3 regenerated
`ion.css` after the two directly imported build inputs changed.

Browser result: **82/82 paired states match computed styles, geometry and exact
full-page pixels**, across **164 HTTP-200 navigations**, with zero page errors
or failed requests. Opened in both themes: threat-intel, integrations, alerts,
discover, settings, analytics, forensics, playbooks, cases, PCAP, chat,
observables, Arkime traffic, templates, About gallery/presenter and daily
standup slides. Additional tabs, panels, namespace cards and shared alert
fields are listed in the evidence report. All 35 final CSS file hashes matched
at run start and completion. The private fixture was stopped and port 8836 has
no listener. Twelve console warnings came from controlled empty EventSource
responses. Earlier four-pixel About-button differences were investigated and
retained in raw evidence; the final entire matrix matched exactly.

The browser fixture uses a private SQLite snapshot, default secret-free
configuration and disabled integrations. This verifies the opened desktop
states, not mobile, live integrations, authentication lifecycle or populated
PCAP analysis. The actual PCAP shell was opened; no capture was fabricated or
uploaded for this CSS task.

The first broad-suite run was interrupted after browser discovery of the live
macro rule. Its partial log is retained and is not counted as a pass. The fresh
12-worker run on the corrected tree completed with exit code **0**:
**11,870 passed, 32 skipped, 2 xfailed, 2 xpassed**, and 2,232 warnings,
in 1,393.42 seconds (23:13). It used `-u`, `-n 12`, `--dist loadfile`,
`-p no:randomly`, no cache provider and a private basetemp. Output was redirected
to a complete log, never piped through tail. No failure reruns were needed.
The pinned-binary CSS gate ran; it did not skip. Warnings include existing
Pydantic deprecations and unavailable optional WeasyPrint native libraries.
