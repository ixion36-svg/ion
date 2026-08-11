/* Alert triage queue — the table half of the /alerts rebuild.
 *
 * Owns column selection, grouping, the keyboard cursor and row rendering. The
 * host page keeps the data, the filters and the actions.
 *
 * Every dependency arrives through mount(). Nothing here reads a global from the
 * host page: alert-detail.js reached for fourteen of alerts.html's top-level
 * `let`s, which were undefined on /cases, and every section that touched one hung
 * on a spinner for three releases. A queue that silently renders nothing would be
 * the same failure with a bigger blast radius.
 */
(function () {
    'use strict';

    const SEVS = ['critical', 'high', 'medium', 'low'];
    const SEVRANK = { critical: 0, high: 1, medium: 2, low: 3 };
    const rank = (s) => (s in SEVRANK ? SEVRANK[s] : 9);

    let host = null;      // everything mount() was given
    let cur = 0;          // cursor index into the flat visible list
    let anchor = null;    // shift-click range anchor
    let sortKey = 'sev';
    let sortDir = 1;
    let groupBy = 'sev';
    let density = 'dense';
    let tz = 'local';
    const collapsed = new Set();
    let bound = false;
    let lastZ = null;   // group z just collapsed, so a second z reopens it

    const esc = (s) => String(s == null ? '' : s).replace(/[&<>"']/g, (c) => ({
        '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;',
    }[c]));

    const p2 = (n) => String(n).padStart(2, '0');

    function ts(a) {
        const t = Date.parse(a && a.timestamp);
        return Number.isNaN(t) ? 0 : t;
    }

    function ageMinutes(a) {
        const t = ts(a);
        return t ? Math.max(0, Math.round((Date.now() - t) / 60000)) : 0;
    }

    function fmtAge(m) {
        if (!m) return '-';
        return m < 60 ? m + 'm' : (m / 60).toFixed(m < 600 ? 1 : 0) + 'h';
    }

    /* Date is always shown: an analyst must never have to work out which day a row
       belongs to. The tooltip is ISO/UTC and labelled, whichever zone is selected. */
    function fmtStamp(a) {
        const t = ts(a);
        if (!t) return '-';
        const d = new Date(t);
        const g = (k) => (tz === 'utc' ? d['getUTC' + k]() : d['get' + k]());
        const mon = ['Jan', 'Feb', 'Mar', 'Apr', 'May', 'Jun',
                     'Jul', 'Aug', 'Sep', 'Oct', 'Nov', 'Dec'][g('Month')];
        return `<span class="aq-d">${p2(g('Date'))} ${mon}</span> `
             + `${p2(g('Hours'))}:${p2(g('Minutes'))}:${p2(g('Seconds'))}`;
    }

    const fmtFull = (a) => (ts(a) ? new Date(ts(a)).toISOString().replace('T', ' ').replace(/\.\d+Z$/, ' UTC') : '');

    const triageOf = (a) => (host.getTriage ? host.getTriage(a.id) : null) || {};
    const statusOf = (a) => {
        const t = triageOf(a);
        return t.status && t.status !== 'none' ? t.status : (a.status || 'open');
    };

    /* ── columns ─────────────────────────────────────────────────────────────
       Every field the page carries is available; `on` is the default set and the
       rest are one click away. Columns whose data the batch triage endpoint does
       not yet return are declared but disabled — see `available`. */
    const COLUMNS = [
        /* Keeps the `alert-checkbox` class and `data-alert-id` the host page's
           bulk-selection code already queries by. Dropping them would leave
           toggleSelectAll / clearSelection / updateBulkActionsUI reaching for
           elements that no longer exist. */
        { k: 'chk', label: '', cls: 'aq-chk', on: true, fixed: true,
          cell: (a) => `<input type="checkbox" class="aq-cb alert-checkbox"`
                     + ` data-alert-id="${esc(a.id)}" tabindex="-1"`
                     + `${host.selection.has(a.id) ? ' checked' : ''}>` },

        { k: 'sev', label: 'Sev', cls: 'aq-sev', on: true, sort: 'sev',
          cell: (a) => `<span class="aq-sev-pill sev-${esc(a.severity)}">${esc(a.severity)}</span>` },

        { k: 'title', label: 'Title', cls: 'aq-title', on: true, sort: 'title',
          cell: (a) => {
              const t = triageOf(a);
              let h = `<span class="aq-t">${esc(a.title)}</span>`;
              if (a.mitre_technique_id) {
                  h += `<span class="aq-tag aq-mitre" title="${esc(a.mitre_technique_name || '')}">`
                     + `${esc(a.mitre_technique_id)}</span>`;
              }
              if (a.is_lab_fixture) h += '<span class="aq-tag aq-lab">lab</span>';
              if (t.case_number && /^\[Auto\]/.test(t.case_title || '')) {
                  h += '<span class="aq-tag aq-auto" title="Auto-cased from Arkime PCAP linkage">auto</span>';
              }
              return h;
          } },

        { k: 'ts', label: 'Timestamp', cls: 'aq-ts', on: true, sort: 'ts',
          cell: (a) => `<span title="${esc(fmtFull(a))}">${fmtStamp(a)}</span>` },

        { k: 'host', label: 'Host', cls: 'aq-host', on: true, sort: 'host',
          cell: (a) => esc(a.host || '-') },

        { k: 'user', label: 'User', cls: 'aq-user', on: true, sort: 'user',
          cell: (a) => esc(a.user || '-') },

        { k: 'src', label: 'System', cls: 'aq-src', on: true, sort: 'source_system',
          cell: (a) => (host.systemBadge ? host.systemBadge(a) : esc(a.source_system || '-')) },

        { k: 'age', label: 'Age', cls: 'aq-age', on: true, sort: 'age',
          cell: (a) => {
              const m = ageMinutes(a);
              return `<span class="${m > 240 ? 'aq-hot' : 'aq-mut'}">${fmtAge(m)}</span>`;
          } },

        { k: 'status', label: 'Status', cls: 'aq-status', on: true, sort: 'status',
          cell: (a) => {
              const s = statusOf(a);
              return `<span class="aq-st aq-st-${esc(s)}">${esc(s)}</span>`;
          } },

        // available, off by default
        { k: 'case', label: 'Case', cls: 'aq-case', on: false, sort: 'case',
          cell: (a) => {
              const t = triageOf(a);
              if (!t.case_number) return '<span class="aq-mut">-</span>';
              const auto = /^\[Auto\]/.test(t.case_title || '');
              return `<span class="aq-tag aq-caseref${auto ? ' aq-autocase' : ''}"`
                   + ` title="${esc(t.case_title || '')}">${esc(t.case_number)}</span>`;
          } },

        { k: 'rule', label: 'Rule', cls: 'aq-rule', on: false, sort: 'rule_name',
          cell: (a) => `<span class="aq-mut" title="${esc(a.rule_name || '')}">${esc(a.rule_name || '-')}</span>` },

        { k: 'tactic', label: 'Tactic', cls: 'aq-tactic', on: false, sort: 'mitre_tactic_name',
          cell: (a) => `<span class="aq-mut">${esc(a.mitre_tactic_name || '-')}</span>` },

        { k: 'srcip', label: 'Source IP', cls: 'aq-ip', on: false, sort: 'source_ip',
          cell: (a) => `<span class="aq-mut aq-mono">${esc(a.source_ip || '-')}</span>` },

        { k: 'dstip', label: 'Dest IP', cls: 'aq-ip', on: false, sort: 'destination_ip',
          cell: (a) => `<span class="aq-mut aq-mono">${esc(a.destination_ip || '-')}</span>` },

        { k: 'node', label: 'Capture node', cls: 'aq-node', on: false, sort: 'arkime_node',
          cell: (a) => `<span class="aq-mut aq-mono">${esc(a.arkime_node || '-')}</span>` },

        // row actions always render last, whatever else is switched on
        { k: 'act', label: '', cls: 'aq-act', on: true, fixed: true, last: true,
          cell: (a) => {
              const t = triageOf(a);
              const pcap = host.arkimeEnabled
                  && (a.network_community_id || a.source_ip || a.destination_ip || a.arkime_node);
              return '<span class="aq-acts">'
                  + `<button class="aq-ra aq-ra-assign" data-aq-act="assign" title="Assign to me">&#9679;</button>`
                  + `<button class="aq-ra aq-ra-ack" data-aq-act="ack" title="Acknowledge">&#10003;</button>`
                  + `<button class="aq-ra aq-ra-case" data-aq-act="case" title="${t.case_number ? 'Already in ' + esc(t.case_number) : 'Create case'}"${t.case_number ? ' disabled' : ''}>&#9634;</button>`
                  + (pcap ? `<a class="aq-ra aq-ra-pcap" data-aq-act="pcap" title="Arkime PCAP analysis">&#9673;</a>` : '')
                  + '</span>';
          } },
    ];

    const shown = () => COLUMNS.filter((c) => c.on && !c.last)
                               .concat(COLUMNS.filter((c) => c.on && c.last));

    /* ── data ────────────────────────────────────────────────────────────── */
    function sortVal(a, k) {
        if (k === 'sev') return rank(a.severity);
        if (k === 'ts' || k === 'age') return ts(a);
        if (k === 'status') return statusOf(a);
        if (k === 'case') return triageOf(a).case_number || '';
        const v = a[k];
        return v == null ? '' : v;
    }

    function sortRows(list) {
        const dir = sortKey === 'age' ? -sortDir : sortDir;   // newest first reads as "age ascending"
        return list.slice().sort((x, y) => {
            const A = sortVal(x, sortKey), B = sortVal(y, sortKey);
            return ((A < B ? -1 : A > B ? 1 : 0) * dir) || (ts(y) - ts(x));
        });
    }

    function groups() {
        const rows = host.getAlerts() || [];
        if (groupBy === 'none') return [{ key: '__all', label: null, items: sortRows(rows) }];
        if (groupBy === 'sev') {
            return SEVS.map((s) => ({
                key: s, label: s, sev: s,
                items: sortRows(rows.filter((a) => a.severity === s)),
            })).filter((g) => g.items.length);
        }
        const m = new Map();
        rows.forEach((a) => {
            const k = (groupBy === 'status' ? statusOf(a) : a[groupBy]) || '(none)';
            if (!m.has(k)) m.set(k, []);
            m.get(k).push(a);
        });
        return [...m.entries()]
            .map(([k, items]) => ({
                key: k, label: k, items: sortRows(items),
                sev: items.slice().sort((x, y) => rank(x.severity) - rank(y.severity))[0].severity,
            }))
            // worst severity first, then the biggest cluster
            .sort((a, b) => rank(a.sev) - rank(b.sev) || b.items.length - a.items.length);
    }

    // the flat list the cursor walks — rows inside a collapsed group are not in it
    const visible = () => groups().filter((g) => !collapsed.has(g.key)).flatMap((g) => g.items);

    function sevMix(items) {
        const total = items.length || 1;
        return '<span class="aq-mix">' + SEVS.map((s) => {
            const n = items.filter((a) => a.severity === s).length;
            return n ? `<i class="sev-${s}" data-aq-w="${(n / total * 100).toFixed(2)}"></i>` : '';
        }).join('') + '</span>';
    }

    /* ── render ──────────────────────────────────────────────────────────── */
    function renderHead() {
        const tr = host.table.querySelector('thead tr');
        tr.innerHTML = shown().map((c) => {
            // id kept: updateBulkActionsUI() and clearSelection() both address it
            if (c.k === 'chk') return '<th class="aq-chk">'
                + '<input type="checkbox" class="aq-all" id="header-select-all"></th>';
            return `<th class="${c.cls}"${c.sort ? ` data-aq-sort="${c.sort}"` : ''}>`
                 + `${esc(c.label)}${c.sort ? `<span class="aq-ar" data-aq-ar="${c.sort}"></span>` : ''}</th>`;
        }).join('');
    }

    function rowHtml(a, i) {
        // `alert-row` + `selected` + data-alert-id are the host page's hooks; the
        // aq-* classes are this module's. Both sets stay on the row.
        const cls = ['aq-row', 'alert-row', 'sv-' + esc(a.severity)];
        if (i === cur) cls.push('aq-cur');
        if (host.selection.has(a.id)) cls.push('aq-picked', 'selected');
        return `<tr class="${cls.join(' ')}" data-aq-id="${esc(a.id)}"`
             + ` data-alert-id="${esc(a.id)}" data-aq-i="${i}">`
             + shown().map((c) => `<td class="${c.cls}">${c.cell(a)}</td>`).join('')
             + '</tr>';
    }

    function render() {
        if (!host) return;
        const tbody = host.table.querySelector('tbody');
        const gs = groups();
        const flat = visible();
        const span = shown().length;

        if (cur >= flat.length) cur = Math.max(0, flat.length - 1);
        host.table.classList.toggle('aq-roomy', density === 'roomy');

        host.table.querySelectorAll('[data-aq-ar]').forEach((e) => {
            e.textContent = e.dataset.aqAr === sortKey ? (sortDir > 0 ? '▲' : '▼') : '';
        });

        if (!flat.length && !gs.length) {
            tbody.innerHTML = `<tr><td colspan="${span}" class="aq-empty">`
                            + 'No alerts match the current filters</td></tr>';
            return;
        }

        let i = 0, html = '';
        for (const g of gs) {
            const shut = collapsed.has(g.key);
            if (g.label !== null) {
                const all = g.items.every((a) => host.selection.has(a.id));
                html += `<tr class="aq-grp" data-aq-g="${esc(g.key)}"><td colspan="${span}">`
                     + `<div class="aq-ghead sev-${esc(g.sev || '')}${shut ? ' aq-closed' : ''}">`
                     + '<span class="aq-gc">&#9662;</span>'
                     + `<span class="aq-gn">${esc(g.label)}</span>`
                     + `<span class="aq-gct">${g.items.length}</span>`
                     + (groupBy !== 'sev' ? sevMix(g.items) : '')
                     + `<button class="aq-gsel" data-aq-gsel="${esc(g.key)}">`
                     + `${all ? 'Deselect' : 'Select'} all</button>`
                     + '</div></td></tr>';
            }
            if (shut) continue;
            for (const a of g.items) html += rowHtml(a, i++);
        }
        tbody.innerHTML = html;

        // percentage widths are a property write, never an inline style attribute
        tbody.querySelectorAll('[data-aq-w]').forEach((el) => {
            el.style.setProperty('width', el.dataset.aqW + '%');
        });

        const row = tbody.querySelector('.aq-cur');
        if (row) row.scrollIntoView({ block: 'nearest' });
        if (host.onRender) host.onRender(flat.length);
    }

    /* ── interaction ─────────────────────────────────────────────────────── */
    function act(kind, ids) {
        if (!ids.length || !host.actions || !host.actions[kind]) return;
        host.actions[kind](ids);
    }

    // With nothing ticked the keyboard acts on the cursor row; with a selection it
    // acts on the selection. Row buttons always act on their own row.
    function targets() {
        const live = [...host.selection];
        if (live.length) return live;
        const a = visible()[cur];
        return a ? [a.id] : [];
    }

    function onTableClick(e) {
        const gsel = e.target.closest('[data-aq-gsel]');
        if (gsel) {
            e.stopPropagation();
            const g = groups().find((x) => String(x.key) === gsel.dataset.aqGsel);
            if (!g) return;
            const all = g.items.every((a) => host.selection.has(a.id));
            g.items.forEach((a) => (all ? host.selection.delete(a.id) : host.selection.add(a.id)));
            if (host.onSelectionChange) host.onSelectionChange();
            render();
            return;
        }

        const grp = e.target.closest('.aq-grp');
        if (grp) {
            const k = grp.dataset.aqG;
            collapsed.has(k) ? collapsed.delete(k) : collapsed.add(k);
            cur = 0; render();
            return;
        }

        const tr = e.target.closest('.aq-row');
        if (!tr) return;
        const list = visible();
        const i = Number(tr.dataset.aqI);
        const a = list[i];
        if (!a) return;

        const ra = e.target.closest('[data-aq-act]');
        if (ra) {
            e.stopPropagation();
            e.preventDefault();
            act(ra.dataset.aqAct, [a.id]);
            return;
        }

        if (e.target.classList.contains('aq-cb') || e.shiftKey) {
            e.stopPropagation();
            if (e.shiftKey && anchor !== null) {
                const lo = Math.min(anchor, i), hi = Math.max(anchor, i);
                for (let n = lo; n <= hi; n++) host.selection.add(list[n].id);
            } else {
                host.selection.has(a.id) ? host.selection.delete(a.id) : host.selection.add(a.id);
                anchor = i;
            }
            cur = i;
            if (host.onSelectionChange) host.onSelectionChange();
            render();
            return;
        }

        cur = i;
        render();
        act('open', [a.id]);
    }

    function onKey(e) {
        if (!host) return;
        if (/input|textarea|select/i.test(e.target.tagName) || e.target.isContentEditable) return;
        if (e.metaKey || e.ctrlKey || e.altKey) return;
        if (host.isBlocked && host.isBlocked()) return;   // a modal owns the keyboard

        const list = visible();
        const k = e.key;
        const move = (next) => {
            lastZ = null;
            if (e.shiftKey && list[cur]) host.selection.add(list[cur].id);
            cur = next;
            if (e.shiftKey && list[cur]) {
                host.selection.add(list[cur].id);
                if (host.onSelectionChange) host.onSelectionChange();
            }
            render();
        };

        if (k === 'j' || k === 'J' || k === 'ArrowDown') { e.preventDefault(); move(Math.min(cur + 1, list.length - 1)); return; }
        if (k === 'k' || k === 'K' || k === 'ArrowUp')   { e.preventDefault(); move(Math.max(cur - 1, 0)); return; }
        if (k === 'g') { cur = 0; render(); return; }
        if (k === 'G') { cur = list.length - 1; render(); return; }
        if (k === 'x') {
            e.preventDefault();
            const a = list[cur];
            if (a) {
                host.selection.has(a.id) ? host.selection.delete(a.id) : host.selection.add(a.id);
                anchor = cur;
                if (host.onSelectionChange) host.onSelectionChange();
                render();
            }
            return;
        }
        if (k === 'z') {
            if (groupBy === 'none') return;
            /* Collapsing removes the cursor's own rows, so the cursor lands in the
               NEXT group — press z again and you would collapse that one too,
               never getting the first back. Remember what z just closed and let a
               second press reopen it; any cursor movement forgets it. */
            if (lastZ !== null && collapsed.has(lastZ)) {
                collapsed.delete(lastZ);
                lastZ = null;
                render();
                return;
            }
            const a = list[cur];
            if (!a) return;
            const key = groupBy === 'sev' ? a.severity
                      : groupBy === 'status' ? statusOf(a) : (a[groupBy] || '(none)');
            // hold the cursor at the position the group occupied rather than
            // sending it back to the top of the queue
            const at = list.findIndex((x) => x.id === a.id);
            const before = list.slice(0, at).filter((x) => {
                const gk = groupBy === 'sev' ? x.severity
                         : groupBy === 'status' ? statusOf(x) : (x[groupBy] || '(none)');
                return gk === key;
            }).length;
            collapsed.add(key);
            lastZ = key;
            cur = Math.max(0, at - before);
            render();
            return;
        }
        if (k === 'Escape') {
            if (host.selection.size) {
                host.selection.clear();
                if (host.onSelectionChange) host.onSelectionChange();
                render();
            }
            return;
        }
        if (k === 'Enter' || k === 'o') { const a = list[cur]; if (a) act('open', [a.id]); return; }
        if (k === 'e') { act('ack', targets()); return; }
        if (k === 'c') { act('case', targets()); return; }
        if (k === 'f') { act('fp', targets()); return; }
        if (k === 'a') { act('assign', targets()); return; }
        if (k === 'b') { const a = list[cur]; if (a) act('bob', [a.id]); return; }
    }

    function bind() {
        if (bound) return;
        bound = true;
        host.table.addEventListener('click', onTableClick);
        host.table.addEventListener('change', (e) => {
            if (!e.target.classList.contains('aq-all')) return;
            const list = visible();
            if (e.target.checked) list.forEach((a) => host.selection.add(a.id));
            else host.selection.clear();
            if (host.onSelectionChange) host.onSelectionChange();
            render();
        });
        host.table.addEventListener('contextmenu', (e) => {
            const tr = e.target.closest('.aq-row');
            if (!tr || !host.actions || !host.actions.context) return;
            e.preventDefault();
            const a = visible()[Number(tr.dataset.aqI)];
            if (!a) return;
            if (!host.selection.has(a.id)) { cur = Number(tr.dataset.aqI); render(); }
            host.actions.context(e, a.id);
        });
        document.addEventListener('keydown', onKey);
    }

    window.ionAlertQueue = {
        /* opts: { table, getAlerts, getTriage, selection:Set, actions:{open,ack,case,fp,assign,bob,pcap,context},
                   systemBadge?, arkimeEnabled?, onSelectionChange?, onRender?, isBlocked? } */
        mount(opts) {
            host = Object.assign({ selection: new Set(), actions: {} }, opts);
            cur = 0; anchor = null; collapsed.clear();
            bind();
            renderHead();
            render();
        },
        render,
        renderHead,
        columns: () => COLUMNS,
        setColumn(k, on) {
            const c = COLUMNS.find((x) => x.k === k);
            if (!c || c.fixed) return;
            c.on = !!on;
            renderHead(); render();
        },
        setGroupBy(v) { groupBy = v; collapsed.clear(); cur = 0; render(); },
        setDensity(v) { density = v; render(); },
        setTimezone(v) { tz = v; render(); },
        setSort(k) {
            if (sortKey === k) sortDir = -sortDir; else { sortKey = k; sortDir = 1; }
            cur = 0; render();
        },
        state: () => ({ groupBy, density, tz, sortKey, sortDir, cursor: cur,
                        visible: visible().length }),
    };
})();
