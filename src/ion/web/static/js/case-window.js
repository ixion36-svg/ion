/**
 * The opened case's window: two layouts, Triage and Read, over one state.
 *
 * The state is one object (S) and apply() is the only thing that writes it
 * to the DOM. Both layouts read the same selection (the ticked alerts),
 * filter, focused alert and case tab, so flipping with the header toggle or
 * `r` keeps all of them.
 *
 * Three nodes exist once and are moved, not re-rendered: the alert detail
 * (#cwin-detail, which hosts the shared alert-detail component, a singleton),
 * the observables list (#cwin-obs) and the key context box (#cwin-kc). In Read
 * the detail sits inside the focused exhibit.
 *
 * The page (cases.html) calls init() once the panel and /api/cases/{id} are
 * in, and focused() from selectCaseAlert. Controls use data-click-action, so
 * every handler below is a window global named cw*.
 */
(function () {
  'use strict';

  var MODE_KEY = 'ion-case-window-mode';
  var KC_LIMIT = 12;
  // Fields that are always present and say nothing about this case: the
  // alert's own time, message and Kibana bookkeeping, and the related.*
  // copies of values shown under their real names.
  var KC_SKIP = ['@timestamp', 'message', 'kibana.', 'signal.', 'related.', 'ecs.',
                 'agent.id', 'agent.ephemeral_id', 'event.ingested', 'event.created',
                 'event.kind', 'event.type', 'event.category', 'event.outcome',
                 'event.dataset', 'event.module', 'event.agent_id_status', 'event.original'];

  // ── triage, without the DOM (tests run these under node) ──────────────
  // An alert is {id, status, verdict, bob}: verdict is the analyst's (a
  // case closure reason, or ''), bob is Bob's or the triage suggestion.
  // verdicts is the fragment's data-verdicts table, in button order.
  var logic = {
    untriaged: function (alerts) {
      return alerts.filter(function (a) { return a.status !== 'closed' && !a.verdict; })
        .map(function (a) { return a.id; });
    },
    untriagedTitle: function (n) { return n + ' linked alert' + (n === 1 ? '' : 's') + ' not triaged'; },
    pillText: function (n) { return n ? n + ' block closure' : 'Nothing blocks closure'; },

    // Everything the window shows that follows from the alerts. `others` is
    // how many blockers do not depend on them (owner, IRIS).
    derive: function (alerts, others, verdicts) {
      var byStatus = { open: 0, acknowledged: 0, closed: 0 };
      alerts.forEach(function (a) { if (a.status in byStatus) byStatus[a.status] += 1; });
      var open = logic.untriaged(alerts).length;
      var blocking = others + (open ? 1 : 0);
      return {
        notClosed: alerts.length - byStatus.closed, byStatus: byStatus,
        untriaged: open, untriagedTitle: logic.untriagedTitle(open),
        blockers: blocking, pill: logic.pillText(blocking),
        suggestion: logic.suggest(alerts, verdicts)
      };
    },

    // The alert window's close, told to leave the case open: the case
    // window records one alert's verdict at a time.
    closeRequest: function (alertId, verdict) {
      return {
        url: '/api/elasticsearch/alerts/' + encodeURIComponent(alertId) + '/close',
        method: 'POST',
        body: { closure_type: verdict.closure_type, notes: null, close_case: false }
      };
    },
    bulkRequests: function (ids, verdict) {
      return ids.map(function (id) { return logic.closeRequest(id, verdict); });
    },

    // The most common verdict across the case's alerts. The analyst's own
    // verdicts count when there are any, else Bob's; a tie goes to the
    // earlier verdict in the table.
    suggest: function (alerts, verdicts) {
      var source = 'analyst';
      var pool = alerts.map(function (a) { return a.verdict; }).filter(Boolean);
      if (!pool.length) {
        source = 'bob';
        pool = alerts.map(function (a) { return a.bob; }).filter(Boolean);
      }
      var best = null;
      verdicts.forEach(function (v) {
        var n = pool.filter(function (r) { return r === v.reason; }).length;
        if (n && (!best || n > best.count)) best = { reason: v.reason, label: v.label, count: n };
      });
      if (!best) return null;
      best.of = alerts.length;
      best.source = source;
      return best;
    },

    // What a key does, or null. Nothing acts while a dialog is open, the
    // popover and a pending bulk confirm take only Escape, and typing keeps
    // every key.
    keyAction: function (c) {
      if (c.mod || c.typing || c.dialog) return null;
      if (c.popover) return c.key === 'Escape' ? 'popover' : null;
      if (c.asking) return c.key === 'Escape' ? 'escape' : null;
      if (c.key === 'r') return 'mode';
      if (c.key === 'j') return 'next';
      if (c.key === 'k') return 'prev';
      if (c.key === 'x') return c.focus ? 'tick' : null;
      if (c.key === 'Escape') return 'escape';
      var v = (c.verdicts || []).filter(function (x) { return x.key === c.key; })[0];
      return v && c.canTriage && c.focus ? 'triage:' + v.reason : null;
    }
  };

  var S = null;
  var root = null;
  var verdicts = [];    // the fragment's data-verdicts
  var docs = {};        // alert id -> raw document, or null when the read failed
  var alertIds = [];    // in rail order
  var letters = {};
  var obsValues = [];

  function esc(s) {
    return String(s == null ? '' : s).replace(/[&<>"']/g, function (c) {
      return { '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c];
    });
  }
  function q(sel) { return root ? root.querySelector(sel) : null; }
  function qa(sel) { return root ? Array.prototype.slice.call(root.querySelectorAll(sel)) : []; }
  function attr(v) {
    if (window.CSS && CSS.escape) return CSS.escape(v);
    return String(v).replace(/\\/g, '\\\\').replace(/"/g, '\\"');
  }
  function rowOf(id) { return q('tr[data-alert-id="' + attr(id) + '"]'); }

  function savedMode() {
    try { return localStorage.getItem(MODE_KEY) === 'read' ? 'read' : 'triage'; } catch (e) { return 'triage'; }
  }

  // ── state -> DOM ──────────────────────────────────────────────────────
  function move(node, host) {
    if (node && host && node.parentNode !== host) host.appendChild(node);
  }

  function visible(id) {
    var row = rowOf(id);
    var st = row ? row.getAttribute('data-status') : '';
    if (S.filter === 'all') return true;
    if (S.filter === 'unclosed') return st !== 'closed';
    if (S.filter === 'untriaged') return st !== 'closed' && !(row && row.getAttribute('data-verdict'));
    return st === S.filter;
  }

  function apply() {
    if (!root) return;
    root.setAttribute('data-mode', S.mode);
    qa('[data-cwin-pane]').forEach(function (p) { p.hidden = p.getAttribute('data-cwin-pane') !== S.mode; });
    qa('[data-mode-btn]').forEach(function (b) {
      var on = b.getAttribute('data-mode-btn') === S.mode;
      b.classList.toggle('on', on);
      b.setAttribute('aria-selected', on ? 'true' : 'false');
    });

    move(document.getElementById('cwin-kc'), q('[data-cwin-kc-home="' + S.mode + '"]'));
    move(document.getElementById('cwin-obs'), q('[data-cwin-obs-home="' + S.mode + '"]'));
    var detail = document.getElementById('cwin-detail');
    var slot = S.mode === 'read' && S.focus ? q('[data-cwin-ex-slot="' + attr(S.focus) + '"]')
      : q('[data-cwin-detail-home="triage"]');
    move(detail, slot);
    qa('.cwin-ex').forEach(function (ex) { ex.classList.toggle('open', ex.getAttribute('data-ex') === S.focus); });

    qa('[data-ctab]').forEach(function (b) { b.classList.toggle('on', b.getAttribute('data-ctab') === S.ctab); });
    qa('[data-cpanel]').forEach(function (p) { p.hidden = p.getAttribute('data-cpanel') !== S.ctab; });

    qa('[data-filt-btn]').forEach(function (b) { b.classList.toggle('on', b.getAttribute('data-filt-btn') === S.filter); });
    qa('tr[data-alert-id]').forEach(function (r) { r.hidden = !visible(r.getAttribute('data-alert-id')); });
    qa('.cwin-ex').forEach(function (ex) { ex.hidden = !visible(ex.getAttribute('data-ex')); });
    var fnote = q('[data-cwin-fnote]');
    if (fnote) {
      fnote.hidden = S.filter === 'all';
      var fname = q('[data-cwin-fname]');
      if (fname) fname.textContent = S.filter === 'unclosed' ? 'not closed' : S.filter;
    }

    qa('[data-click-action="cwPick"]').forEach(function (cb) {
      var id = JSON.parse(cb.getAttribute('data-args'))[0];
      cb.checked = S.picks.has(id);
    });
    var all = q('[data-cwin-pickall]');
    if (all) {
      all.checked = S.picks.size > 0 && S.picks.size === alertIds.length;
      all.indeterminate = S.picks.size > 0 && S.picks.size < alertIds.length;
    }
    var bulk = q('[data-cwin-bulk]');
    if (bulk) {
      bulk.hidden = !S.picks.size;
      var n = q('[data-cwin-selcount]');
      if (n) n.textContent = S.picks.size + ' ticked';
      if (!S.picks.size) S.ask = null;
      var ask = q('[data-cwin-bulk-ask]');
      if (ask) ask.hidden = !S.ask;
      var acts = q('[data-cwin-bulk-acts]');
      if (acts) acts.hidden = !!S.ask;
      var res = q('[data-cwin-bulk-res]');
      if (res && !S.picks.size) res.hidden = true;
    }
    qa('tr[data-alert-id], .cwin-ex').forEach(function (el) {
      var id = el.getAttribute('data-alert-id') || el.getAttribute('data-ex');
      el.classList.toggle('cwin-picked', S.picks.has(id));
      el.classList.toggle('cwin-hit', !!(S.find && S.find.ids.indexOf(id) !== -1));
    });

    scopeObservables();
    renderKc();
  }

  // ── key context ───────────────────────────────────────────────────────
  function scope() {
    return S.picks.size ? alertIds.filter(function (id) { return S.picks.has(id); }) : alertIds.slice();
  }

  function skip(name) {
    return KC_SKIP.some(function (p) { return name === p || name.indexOf(p) === 0; });
  }

  function kcRows() {
    var byKey = {};
    var rows = [];
    var unread = 0;
    var pending = 0;
    scope().forEach(function (id) {
      if (!(id in docs)) { pending += 1; return; }
      if (!docs[id]) { unread += 1; return; }
      window.ionAlertDetail.highlightedFields(docs[id]).forEach(function (f) {
        if (skip(f.n)) return;
        var key = f.n + '\u0000' + f.v;
        if (!byKey[key]) { byKey[key] = { n: f.n, v: f.v, ids: [] }; rows.push(byKey[key]); }
        if (byKey[key].ids.indexOf(id) === -1) byKey[key].ids.push(id);
      });
    });
    rows.forEach(function (r) { r.obs = obsValues.indexOf(String(r.v).toLowerCase()) !== -1; });
    rows.sort(function (a, b) {
      return (b.ids.length - a.ids.length) || ((b.obs ? 1 : 0) - (a.obs ? 1 : 0)) || (a.n < b.n ? -1 : a.n > b.n ? 1 : 0);
    });
    return { rows: rows, unread: unread, pending: pending };
  }

  function lettersOf(ids) {
    return ids.map(function (id) { return letters[id] || '?'; });
  }

  function renderKc() {
    var box = document.getElementById('cwin-kc');
    if (!box || !window.ionAlertDetail || !window.ionAlertDetail.highlightedFields) return;
    var res = kcRows();
    var ids = scope();
    var head = q('[data-cwin-kc-scope]');
    if (head) {
      head.innerHTML = S.picks.size
        ? '<b>' + ids.length + ' ticked</b> from exhibit' + (ids.length === 1 ? ' ' : 's ') + esc(lettersOf(ids).join(', '))
          + ' · ×n is how many of them carry it <button type="button" class="cwin-link" data-click-action="cwClearPicks">Show whole case</button>'
        : 'Highlighted fields across all ' + ids.length + ' alert' + (ids.length === 1 ? '' : 's')
          + ' · ×n is how many carry it · click one to find them';
    }
    var shown = S.kcAll ? res.rows : res.rows.slice(0, KC_LIMIT);
    var more = q('[data-cwin-kc-all]');
    if (more) {
      more.hidden = res.rows.length <= KC_LIMIT;
      more.textContent = S.kcAll ? 'Show fewer' : 'Show all ' + res.rows.length;
    }
    var note = '';
    if (res.pending) note += '<span class="cwin-note">Reading ' + res.pending + ' alert document' + (res.pending === 1 ? '' : 's') + '…</span>';
    if (res.unread) note += '<span class="cwin-note">' + res.unread + ' alert document' + (res.unread === 1 ? '' : 's')
      + ' could not be read, so ' + (res.unread === 1 ? 'its' : 'their') + ' fields are missing here.</span>';
    var chips = q('[data-cwin-kc-chips]');
    if (!chips) return;
    if (!shown.length) {
      chips.innerHTML = note || '<span class="cwin-note">These alerts have no highlighted fields.</span>';
      return;
    }
    var isFound = function (r) { return S.find && S.find.n === r.n && S.find.v === r.v; };
    if (S.mode === 'read') {
      chips.innerHTML = '<table class="cwin-kct"><thead><tr><th>Field</th><th>Value</th><th>Carried by</th></tr></thead><tbody>'
        + shown.map(function (r) {
          return '<tr class="' + (isFound(r) ? 'on' : '') + '"><td class="cwin-mono">' + esc(r.n) + '</td><td class="cwin-mono cwin-break">'
            + esc(r.v) + (r.obs ? ' <span class="cwin-obsmark" title="An observable on this case">✓</span>' : '') + '</td>'
            + '<td><button type="button" class="cwin-link" data-click-action="cwKcFind" data-args="'
            + esc(JSON.stringify([r.n, r.v])) + '">×' + r.ids.length + ' · '
            + (r.ids.length === ids.length && ids.length > 1 ? 'every one'
               : r.ids.length <= 8 ? esc(lettersOf(r.ids).join(' ')) : 'find them') + '</button></td></tr>';
        }).join('') + '</tbody></table>' + note;
      return;
    }
    chips.innerHTML = shown.map(function (r) {
      return '<button type="button" class="cwin-kchip' + (isFound(r) ? ' on' : '') + '" title="' + esc(r.n + ' = ' + r.v) + '"'
        + ' data-click-action="cwKcFind" data-args="' + esc(JSON.stringify([r.n, r.v])) + '">'
        + '<span class="cwin-kk">' + esc(r.n) + '</span><span class="cwin-kv">' + esc(r.v) + '</span>'
        + (r.obs ? '<span class="cwin-obsmark" title="An observable on this case">✓</span>' : '')
        + '<span class="cwin-kn">×' + r.ids.length + '</span></button>';
    }).join('') + note;
  }

  function scopeObservables() {
    var cards = qa('.cwin-ob');
    var n = 0;
    cards.forEach(function (c) {
      var ids = [];
      try { ids = JSON.parse(c.getAttribute('data-ob-alerts') || '[]'); } catch (e) { ids = []; }
      var on = !S.picks.size || ids.some(function (id) { return S.picks.has(id); });
      c.hidden = !on;
      if (on) n += 1;
    });
    var note = q('[data-cwin-obs-scope]');
    if (note) note.textContent = S.picks.size ? n + ' of ' + cards.length + ' carried by the ticked alerts' : '';
  }

  // ── what the raw documents add to the rows ────────────────────────────
  function first(raw, paths) {
    for (var i = 0; i < paths.length; i++) {
      var v = paths[i].split('.').reduce(function (o, k) { return (o && typeof o === 'object') ? o[k] : undefined; }, raw);
      if (v === undefined) v = raw[paths[i]];
      if (Array.isArray(v)) v = v[0];
      if (v !== undefined && v !== null && String(v) !== '') return String(v);
    }
    return null;
  }

  function hhmm(ts) {
    var d = new Date(ts);
    if (isNaN(d.getTime())) return null;
    return d.toISOString().slice(5, 16).replace('T', ' ');
  }

  function fillRow(id) {
    var raw = docs[id];
    var when = raw ? hhmm(first(raw, ['@timestamp', 'event.created'])) : null;
    qa('[data-cwin-time="' + attr(id) + '"]').forEach(function (el) {
      el.textContent = raw === null ? 'unread' : (when || 'no time');
      el.title = raw === null ? 'The alert document could not be read' : (when ? 'UTC' : 'The document has no @timestamp');
    });
    if (!raw) return;
    var host = first(raw, ['host.name', 'host.hostname', 'agent.name', 'winlog.computer_name']);
    qa('[data-cwin-host="' + attr(id) + '"]').forEach(function (el) { el.textContent = host || ''; });
    var line = q('[data-cwin-exline="' + attr(id) + '"]');
    if (line) {
      var cmd = first(raw, ['process.command_line', 'kibana.alert.reason', 'message']);
      if (!line.hasAttribute('data-cwin-base')) line.setAttribute('data-cwin-base', line.textContent);
      line.textContent = [cmd, host, line.getAttribute('data-cwin-base')].filter(Boolean).join(' · ');
    }
    var pk = q('[data-cwin-expk="' + attr(id) + '"]');
    if (pk) {
      var f = window.ionAlertDetail.highlightedFields(raw).filter(function (x) { return !skip(x.n); });
      pk.innerHTML = f.slice(0, 3).map(function (x) {
        return '<span class="cwin-pk"><b>' + esc(x.n) + '</b><span class="cwin-mono">' + esc(x.v) + '</span></span>';
      }).join('') + (f.length > 3 ? '<span class="cwin-note">+' + (f.length - 3) + ' highlighted · open it to read them</span>' : '');
    }
    if (S.focus === id) describeFocus();
  }

  // Four at a time: a twenty-alert case should not open twenty connections.
  function loadDocs() {
    var queue = alertIds.filter(function (id) { return !(id in docs); });
    var fetchRaw = window.ionAlertDetailFetchRaw;
    if (!fetchRaw) return;
    var pending = false;
    function redraw() {
      if (pending) return;
      pending = true;
      requestAnimationFrame(function () { pending = false; renderKc(); });
    }
    function next() {
      var id = queue.shift();
      if (id === undefined) return;
      fetchRaw(id).then(function (raw) { docs[id] = raw || null; }, function () { docs[id] = null; })
        .then(function () { fillRow(id); redraw(); next(); });
    }
    for (var i = 0; i < 4; i++) next();
  }

  // ── the detail's own head ─────────────────────────────────────────────
  function describeFocus() {
    var id = S.focus;
    var row = rowOf(id);
    if (!row) return;
    var raw = docs[id];
    var host = raw ? first(raw, ['host.name', 'host.hostname', 'agent.name']) : null;
    var when = raw ? hhmm(first(raw, ['@timestamp'])) : null;
    var set = function (sel, text) { var el = q(sel); if (el) el.textContent = text; };
    set('[data-cwin-d-letter]', 'Exhibit ' + (letters[id] || '?'));
    set('[data-cwin-d-when]', [when, host].filter(Boolean).map(function (x) { return ' · ' + x; }).join(''));
    var name = row.querySelector('.cpanel-rail-alert-name');
    set('[data-cwin-d-title]', name ? name.textContent : id);
    var meta = q('[data-cwin-d-meta]');
    if (meta) {
      meta.replaceChildren();
      row.querySelectorAll('.cwin-sev, .cpanel-alert-badge, .cwin-verdict:not([hidden])').forEach(function (b) {
        meta.appendChild(b.cloneNode(true));
      });
    }
    var verdict = row.getAttribute('data-verdict');
    qa('[data-cwin-tvs] [data-tv]').forEach(function (b) {
      var on = b.getAttribute('data-tv') === verdict;
      b.classList.toggle('on', on);
      b.setAttribute('aria-pressed', on ? 'true' : 'false');
    });
    var bob = q('template[data-bob-for="' + attr(id) + '"]');
    var slot = document.getElementById('cwin-bob-slot');
    if (slot) slot.replaceChildren(bob ? bob.content.cloneNode(true) : document.createTextNode(''));
  }

  // ── public: called by the page ────────────────────────────────────────
  function init(body, kase) {
    root = body.querySelector('[data-cwin]');
    if (!root) return;
    alertIds = qa('tr[data-alert-id]').map(function (r) { return r.getAttribute('data-alert-id'); });
    letters = {};
    qa('tr[data-alert-id]').forEach(function (r) {
      var l = r.querySelector('.cwin-letter');
      letters[r.getAttribute('data-alert-id')] = l ? l.textContent : '?';
    });
    try { obsValues = JSON.parse(root.getAttribute('data-obs-values') || '[]'); } catch (e) { obsValues = []; }
    try { verdicts = JSON.parse(root.getAttribute('data-verdicts') || '[]'); } catch (e) { verdicts = []; }
    var keep = S && S.caseId === (kase && kase.id);
    if (!keep) {
      S = { caseId: kase && kase.id, mode: savedMode(), focus: root.getAttribute('data-first-alert-id') || null,
            picks: new Set(), filter: 'all', ctab: 'kc', kcAll: false, find: null };
      docs = {};
    } else {
      S.picks.forEach(function (id) { if (alertIds.indexOf(id) === -1) S.picks.delete(id); });
    }
    apply();
    recount();
    alertIds.forEach(function (id) { if (id in docs) fillRow(id); });
    loadDocs();
  }

  function focused(id) {
    if (!S) return;
    S.focus = id;
    qa('tr[data-alert-id]').forEach(function (r) { r.classList.toggle('selected', r.getAttribute('data-alert-id') === id); });
    describeFocus();
    apply();
  }

  function focusAlert(id) {
    var row = rowOf(id);
    if (!row || typeof window.selectCaseAlert !== 'function') return;
    var args = JSON.parse(row.getAttribute('data-args'));
    window.selectCaseAlert(args[0], args[1], args[2]);
    if (S.mode === 'read') {
      var ex = q('[data-ex="' + attr(id) + '"]');
      if (ex) ex.scrollIntoView({ block: 'start', behavior: 'smooth' });
    } else {
      row.scrollIntoView({ block: 'nearest' });
    }
  }

  function setMode(mode) {
    if (!S) return;
    S.mode = mode === 'read' ? 'read' : 'triage';
    try { localStorage.setItem(MODE_KEY, S.mode); } catch (e) { /* per-viewer convenience only */ }
    apply();
    if (S.mode === 'read' && S.focus) {
      var ex = q('[data-ex="' + attr(S.focus) + '"]');
      if (ex) ex.scrollIntoView({ block: 'start' });
    }
  }

  function step(delta) {
    var ids = alertIds.filter(visible);
    if (!ids.length) return;
    var i = ids.indexOf(S.focus);
    var next = ids[Math.max(0, Math.min(ids.length - 1, i === -1 ? 0 : i + delta))];
    if (next && next !== S.focus) focusAlert(next);
  }

  function togglePick(id, on) {
    if (on === undefined) on = !S.picks.has(id);
    if (on) S.picks.add(id); else S.picks.delete(id);
    apply();
  }

  // ── triage ────────────────────────────────────────────────────────────
  // The rows' data-status and data-verdict are the alerts' state; every
  // count, the blockers and the suggestion are recomputed from them.
  function alertModel() {
    return qa('tr[data-alert-id]').map(function (r) {
      return { id: r.getAttribute('data-alert-id'), status: r.getAttribute('data-status'),
               verdict: r.getAttribute('data-verdict') || '', bob: r.getAttribute('data-bob-verdict') || '' };
    });
  }
  function verdictOf(reason) { return verdicts.filter(function (v) { return v.reason === reason; })[0] || null; }
  function toast(msg, kind) { if (typeof window.showToast === 'function') window.showToast(msg, kind); }

  function suggestionText(s) {
    if (!s) return 'No alert carries a verdict yet, so there is no suggested reason.';
    return 'Suggested reason: ' + s.label + ', the most common verdict (' + s.count + ' of ' + s.of
      + ' alert' + (s.of === 1 ? '' : 's') + ', ' + (s.source === 'analyst' ? 'yours' : "Bob's")
      + '). A suggestion, not a rule.';
  }

  function recount() {
    var model = alertModel();
    var others = qa('[data-cwin-pill-list] [data-cwin-bl]').filter(function (li) {
      return !li.hidden && li.getAttribute('data-cwin-bl') !== 'alerts';
    }).length;
    var d = logic.derive(model, others, verdicts);
    var n = q('[data-cwin-notclosed]');
    if (n) n.textContent = d.notClosed;
    qa('[data-cwin-fcount]').forEach(function (el) {
      var s = el.getAttribute('data-cwin-fcount');
      el.textContent = d.byStatus[s];
      el.closest('[data-filt-btn]').hidden = !d.byStatus[s] && S.filter !== s;
    });
    qa('[data-cwin-bl="alerts"]').forEach(function (li) {
      li.hidden = !d.untriaged;
      var t = li.querySelector('[data-cwin-bl-title]');
      if (t) t.textContent = d.untriagedTitle;
    });
    var pill = q('[data-cwin-pill]');
    if (pill) pill.classList.toggle('clear', !d.blockers);
    var label = q('[data-cwin-pill-n]');
    if (label) label.textContent = d.pill;
    qa('[data-cwin-bl-none]').forEach(function (p) { p.hidden = !!d.blockers; });
    var sug = q('[data-cwin-suggest]');
    if (sug) sug.textContent = suggestionText(d.suggestion);
  }

  function setBadge(holder, status, reason) {
    if (!holder) return;
    holder.setAttribute('data-status', status);
    holder.setAttribute('data-verdict', reason);
    var badge = holder.querySelector('.cpanel-alert-badge');
    if (badge) {
      badge.textContent = status;
      badge.className = 'cpanel-alert-badge status-' + status;
    }
    var chip = holder.querySelector('[data-cwin-verdict]');
    var v = verdictOf(reason);
    if (chip) {
      chip.hidden = !v;
      chip.textContent = v ? v.label : '';
      chip.className = 'cwin-verdict' + (v ? ' v-' + v.reason : '');
    }
  }

  function recorded(id, status, reason) {
    setBadge(rowOf(id), status, reason);
    setBadge(q('.cwin-ex[data-ex="' + attr(id) + '"]'), status, reason);
    recount();
    if (S.focus === id) describeFocus();
    apply();
  }

  function post(req) {
    return fetch(req.url, {
      method: req.method, headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(req.body)
    }).then(function (r) {
      return r.json().catch(function () { return {}; }).then(function (d) {
        if (!r.ok) throw new Error((d && d.detail) || ('HTTP ' + r.status));
        return d;
      });
    });
  }

  // Resolves to {id, ok, error}; never rejects, so a bulk run reports each.
  function triageOne(id, v) {
    var row = rowOf(id);
    if (row) row.classList.add('cwin-busy');
    return post(logic.closeRequest(id, v)).then(function (d) {
      recorded(id, (d && d.status) || 'closed', v.reason);
      return { id: id, ok: true };
    }, function (e) {
      return { id: id, ok: false, error: (e && e.message) || String(e) };
    }).then(function (res) {
      if (row) row.classList.remove('cwin-busy');
      return res;
    });
  }

  function triageMany(ids, v) {
    var queue = ids.slice();
    var results = [];
    function worker() {
      var id = queue.shift();
      if (id === undefined) return Promise.resolve();
      return triageOne(id, v).then(function (r) { results.push(r); return worker(); });
    }
    var workers = [];
    for (var i = 0; i < Math.min(4, ids.length); i++) workers.push(worker());
    return Promise.all(workers).then(function () { return results; });
  }

  function reportBulk(results, v) {
    var failed = results.filter(function (r) { return !r.ok; });
    var done = results.length - failed.length;
    S.picks = new Set(failed.map(function (r) { return r.id; }));
    S.ask = null;
    apply();
    var box = q('[data-cwin-bulk-res]');
    if (box) {
      box.hidden = !failed.length;
      box.innerHTML = failed.length
        ? '<b>' + done + ' marked ' + esc(v.label.toLowerCase()) + ', ' + failed.length + ' failed.</b> Still ticked:<ul>'
          + failed.map(function (r) {
            return '<li><span class="cwin-letter">' + esc(letters[r.id] || '?') + '</span> ' + esc(r.error) + '</li>';
          }).join('') + '</ul>'
        : '';
    }
    if (done) toast(done + ' alert' + (done === 1 ? '' : 's') + ' marked ' + v.label.toLowerCase(), 'success');
    if (failed.length) toast(failed.length + ' alert' + (failed.length === 1 ? '' : 's') + ' could not be marked', 'error');
  }

  function triageFocused(reason) {
    var v = verdictOf(reason);
    var id = S && S.focus;
    if (!v || !id) return;
    var row = rowOf(id);
    if (row && row.classList.contains('cwin-busy')) return;
    triageOne(id, v).then(function (r) {
      if (!r.ok) { toast('Exhibit ' + (letters[id] || '?') + ' could not be marked: ' + r.error, 'error'); return; }
      toast('Exhibit ' + (letters[id] || '?') + ' marked ' + v.label.toLowerCase(), 'success');
      if (!visible(id)) step(1);
    });
  }

  function closePill() {
    var list = q('[data-cwin-pill-list]');
    if (list && !list.hidden) window.cwTogglePill();
  }

  // The close dialog belongs to cases.html. Its body gets this window's
  // warnings and the suggested reason each time it is opened from here.
  function fillCloseDialog() {
    var overlay = document.getElementById('closure-modal-overlay');
    var select = document.getElementById('closure-reason');
    var tpl = q('template[data-cwin-close-extra]');
    if (!overlay || !select || !tpl) return;
    dropCloseExtra();
    var extra = tpl.content.firstElementChild.cloneNode(true);
    var items = qa('[data-cwin-pill-list] [data-cwin-bl]').filter(function (li) { return !li.hidden; });
    var list = extra.querySelector('[data-cwin-cx-list]');
    items.forEach(function (li) {
      var copy = li.cloneNode(true);
      copy.removeAttribute('data-cwin-bl');
      copy.querySelectorAll('button').forEach(function (b) { b.remove(); });
      list.appendChild(copy);
    });
    extra.querySelector('[data-cwin-cx-n]').textContent = items.length;
    extra.querySelector('[data-cwin-cx-warn]').hidden = !items.length;
    var s = logic.suggest(alertModel(), verdicts);
    var line = extra.querySelector('[data-cwin-cx-suggest]');
    if (s) {
      select.value = s.reason;
      if (typeof window.highlightClosureGuide === 'function') window.highlightClosureGuide();
      line.hidden = false;
      line.textContent = suggestionText(s);
    }
    var anchor = select.closest('.mb-3') || select;
    anchor.parentNode.insertBefore(extra, anchor);
  }
  function dropCloseExtra() {
    var old = document.querySelector('#closure-modal-overlay [data-cwin-cx]');
    if (old) old.remove();
  }

  // ── handlers named by data-click-action ───────────────────────────────
  window.cwTriage = function (reason) { triageFocused(reason); };
  window.cwBulkTriage = function (reason) {
    if (!S || !S.picks.size) return;
    var v = verdictOf(reason);
    if (!v) return;
    var ids = alertIds.filter(function (id) { return S.picks.has(id); });
    if (ids.length === 1) { triageMany(ids, v).then(function (r) { reportBulk(r, v); }); return; }
    S.ask = { reason: reason, ids: ids };
    var qn = q('[data-cwin-bulk-q]');
    if (qn) qn.innerHTML = 'Mark <b>' + ids.length + ' alerts</b> (' + esc(lettersOf(ids).join(', ')) + ') <b>'
      + esc(v.label.toLowerCase()) + '</b>?';
    apply();
  };
  window.cwBulkConfirm = function () {
    if (!S || !S.ask) return;
    var v = verdictOf(S.ask.reason);
    var ids = S.ask.ids;
    S.ask = null;
    apply();
    triageMany(ids, v).then(function (r) { reportBulk(r, v); });
  };
  window.cwBulkCancel = function () { if (!S) return; S.ask = null; apply(); };

  // Take alerts out of the case. Acknowledged ones go back to open, so they
  // return to the alert queue; the window then re-reads the case.
  function removeFromCase(ids) {
    if (!S || !S.caseId || !ids.length) return;
    var what = ids.length === 1
      ? 'exhibit ' + (letters[ids[0]] || '?')
      : ids.length + ' alerts (' + lettersOf(ids).join(', ') + ')';
    var ask = ['Remove ' + what + ' from this case?', '',
      'Acknowledged alerts go back to open in the alert queue.'].join(String.fromCharCode(10));
    if (!window.confirm(ask)) return;
    post({ url: '/api/cases/' + encodeURIComponent(S.caseId) + '/alerts/remove', method: 'POST',
           body: { alert_ids: ids } })
      .then(function (d) {
        var n = (d && d.removed) || 0;
        toast(n + ' alert' + (n === 1 ? '' : 's') + ' removed from the case', n ? 'success' : 'warning');
        S.picks = new Set();
        if (typeof window.openCaseDetail === 'function') window.openCaseDetail(S.caseId);
        if (typeof window.loadAllCases === 'function') window.loadAllCases();
      }, function (e) { toast('Could not remove: ' + ((e && e.message) || e), 'error'); });
  }
  window.cwRemovePicked = function () {
    if (!S) return;
    removeFromCase(alertIds.filter(function (id) { return S.picks.has(id); }));
  };
  window.cwRemoveFocused = function () { if (S && S.focus) removeFromCase([S.focus]); };
  window.cwTriageThem = function () {
    if (!S) return;
    closePill();
    if (S.mode !== 'triage') setMode('triage');
    S.picks = new Set(logic.untriaged(alertModel()));
    S.filter = 'all';
    apply();
    var firstPick = q('tr.cwin-picked');
    if (firstPick) firstPick.scrollIntoView({ block: 'nearest' });
    var bulk = q('[data-cwin-bulk]');
    if (bulk) bulk.scrollIntoView({ block: 'nearest', behavior: 'smooth' });
  };
  window.cwAssignMe = function (caseId, userId) {
    closePill();
    post({ url: '/api/cases/' + encodeURIComponent(caseId), method: 'PATCH', body: { assigned_to_id: userId } })
      .then(function () {
        toast('Case assigned to you', 'success');
        if (typeof window.openCaseDetail === 'function') window.openCaseDetail(caseId);
      }, function (e) { toast('Could not assign the case: ' + ((e && e.message) || e), 'error'); });
  };
  window.cwCloseCase = function (caseId) {
    if (typeof window.panelUpdateField !== 'function') return;
    closePill();
    window.panelUpdateField(caseId, 'status', 'closed');
    fillCloseDialog();
  };

  window.cwSetMode = setMode;
  window.cwFocusAlert = focusAlert;
  window.cwCaseTab = function (tab) { if (!S) return; S.ctab = tab === 'observables' ? 'observables' : 'kc'; apply(); };
  window.cwFilter = function (f) {
    if (!S) return;
    S.filter = ['all', 'unclosed', 'untriaged', 'open', 'acknowledged', 'closed'].indexOf(f) !== -1 ? f : 'all';
    var list = q('[data-cwin-pill-list]');
    if (list) list.hidden = true;
    apply();
  };
  window.cwPick = function (id, on) { if (S) togglePick(id, !!on); };
  window.cwPickAll = function (on) {
    if (!S) return;
    S.picks = on ? new Set(alertIds) : new Set();
    apply();
  };
  window.cwClearPicks = function () { if (!S) return; S.picks = new Set(); S.find = null; apply(); };
  window.cwKcAll = function () { if (!S) return; S.kcAll = !S.kcAll; renderKc(); };
  window.cwKcFind = function (n, v) {
    if (!S) return;
    var same = S.find && S.find.n === n && S.find.v === v;
    if (same) { S.find = null; apply(); return; }
    var ids = alertIds.filter(function (id) {
      return docs[id] && window.ionAlertDetail.highlightedFields(docs[id]).some(function (f) { return f.n === n && f.v === v; });
    });
    S.find = { n: n, v: v, ids: ids };
    apply();
    var firstHit = S.mode === 'read' ? q('.cwin-ex.cwin-hit') : q('tr.cwin-hit');
    if (firstHit) firstHit.scrollIntoView({ block: 'nearest', behavior: 'smooth' });
  };
  window.cwTogglePill = function () {
    var list = q('[data-cwin-pill-list]');
    if (!list) return;
    list.hidden = !list.hidden;
    var b = q('.cwin-pill-b');
    if (b) b.setAttribute('aria-expanded', list.hidden ? 'false' : 'true');
  };
  window.cwGoto = function (id) {
    if (!S) return;
    if (S.mode !== 'read') setMode('read');
    var list = q('[data-cwin-pill-list]');
    if (list) list.hidden = true;
    var el = document.getElementById(id);
    if (el) el.scrollIntoView({ block: 'start', behavior: 'smooth' });
  };
  window.cwToggleOb = function () {
    var card = this && this.closest ? this.closest('.cwin-ob') : null;
    if (!card) return;
    var b = card.querySelector('.cwin-obb');
    b.hidden = !b.hidden;
    card.classList.toggle('open', !b.hidden);
    var t = card.querySelector('.cwin-x');
    if (t) t.setAttribute('aria-expanded', b.hidden ? 'false' : 'true');
  };
  window.cwShowObservable = function (value) {
    if (!S) return;
    var card = qa('.cwin-ob').filter(function (c) { return c.getAttribute('data-ob-value') === String(value).toLowerCase(); })[0];
    if (!card) return;
    if (S.mode === 'triage') S.ctab = 'observables';
    S.picks = new Set();
    apply();
    var b = card.querySelector('.cwin-obb');
    if (b && b.hidden) window.cwToggleOb.call(card.querySelector('.cwin-x'));
    card.scrollIntoView({ block: 'center', behavior: 'smooth' });
  };

  // On-demand enrichment. The answer is shown in the card and not stored:
  // POST /api/enrichment/lookup returns it and keeps nothing.
  window.cwLookup = function (type, value) {
    var card = this && this.closest ? this.closest('.cwin-ob') : null;
    var out = card && card.querySelector('[data-cwin-lookup]');
    if (!out) return;
    out.hidden = false;
    out.textContent = 'Asking the enabled providers…';
    fetch('/api/enrichment/lookup', {
      method: 'POST', headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ ioc_type: type, value: value })
    }).then(function (r) {
      return r.json().catch(function () { return {}; }).then(function (d) {
        if (!r.ok) throw new Error((d && d.detail) || ('HTTP ' + r.status));
        return d;
      });
    }).then(function (d) {
      var providers = (d && d.providers) || [];
      if (!providers.length) {
        out.textContent = (d && d.message) || 'No enrichment provider is enabled, so nothing was looked up.';
        return;
      }
      var res = (d && d.results) || {};
      out.innerHTML = providers.map(function (p) {
        var r = res[p] || {};
        var state = r.error ? 'failed: ' + r.error : r.skipped ? 'does not take this type'
          : (r.found === false ? 'no match' : 'answered');
        // Providers answer in their own shapes; their flat fields are shown as given.
        var rows = (!r.error && !r.skipped && r.found !== false) ? Object.keys(r).filter(function (k) {
          return ['source', 'found', 'raw'].indexOf(k) === -1 && r[k] !== null && typeof r[k] !== 'object';
        }).slice(0, 6).map(function (k) { return '<dt>' + esc(k) + '</dt><dd>' + esc(r[k]) + '</dd>'; }).join('') : '';
        return '<div class="cwin-src"><b>' + esc(p) + '</b><span class="cwin-note">' + esc(state) + '</span>'
          + (rows ? '<dl>' + rows + '</dl>' : '') + '</div>';
      }).join('') + '<p class="cwin-note">Shown, not saved.</p>';
    }).catch(function (e) {
      out.textContent = 'The lookup failed: ' + ((e && e.message) || e);
    });
  };

  // ── keys ──────────────────────────────────────────────────────────────
  document.addEventListener('keydown', function (e) {
    var panel = document.getElementById('case-panel');
    if (!S || !root || !document.body.contains(root) || (panel && !panel.classList.contains('open'))) return;
    var t = e.target;
    var typing = !!t && (t.isContentEditable || /^(TEXTAREA|SELECT)$/.test(t.tagName)
      || (t.tagName === 'INPUT' && !/^(checkbox|radio|button)$/.test(t.type)));
    if (typing && e.key === 'Escape' && t.blur) t.blur();
    var list = q('[data-cwin-pill-list]');
    var action = logic.keyAction({
      key: e.key, mod: e.ctrlKey || e.metaKey || e.altKey, typing: typing, dialog: dialogOpen(),
      popover: !!list && !list.hidden, asking: !!S.ask, focus: S.focus, canTriage: !!q('[data-cwin-tvs]'), verdicts: verdicts
    });
    if (!action) return;
    if (action !== 'escape' && action !== 'popover') e.preventDefault();
    if (action === 'mode') setMode(S.mode === 'read' ? 'triage' : 'read');
    else if (action === 'next') step(1);
    else if (action === 'prev') step(-1);
    else if (action === 'tick') togglePick(S.focus);
    else if (action === 'popover') window.cwTogglePill();
    else if (action === 'escape') {
      if (S.ask) { S.ask = null; apply(); return; }
      S.picks = new Set(); S.find = null; apply();
    } else if (action.indexOf('triage:') === 0) triageFocused(action.slice(7));
  });

  // The page opens its dialogs with style.display, not a class; the
  // alert-detail component appends its own overlays to the body.
  function dialogOpen() {
    return ['closure-modal-overlay', 'create-case-overlay'].some(function (id) {
      var m = document.getElementById(id); return m && m.style.display === 'flex';
    }) || !!document.querySelector('#iad-tune-overlay, #alert-closure-modal-overlay');
  }

  document.addEventListener('click', function (e) {
    var tabBtn = e.target.closest && e.target.closest('#cpanel-alert-workspace .detail-tab-btn');
    if (S && tabBtn) S.tab = tabBtn.getAttribute('data-tab');
    var list = q('[data-cwin-pill-list]');
    if (list && !list.hidden && !e.target.closest('[data-cwin-pill]')) window.cwTogglePill();
    if (e.target.closest && e.target.closest('#closure-modal-overlay [data-click-action="cancelClosure"],'
        + ' #closure-modal-overlay [data-click-action="confirmClosure"]')) setTimeout(dropCloseExtra, 0);
  });

  window.ionCaseWindow = { init: init, focused: focused, setMode: setMode, logic: logic, get state() { return S; } };
})();
