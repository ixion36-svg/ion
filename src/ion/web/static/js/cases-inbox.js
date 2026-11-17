/*
 * The /cases inbox: selection, the preview pane, the chips, the keys, and the
 * list's state across a trip into a case and back.
 *
 * renderBoard in cases.html still reads each page from /ui/cases/board; it
 * calls params() before the request and rendered() after the swap.
 *
 * The state lives in sessionStorage because opening a case is a navigation
 * to /cases/{id}: coming back is a fresh page load, and without it the
 * filters and the selected row would be gone.
 */
(function () {
  'use strict';

  var STORE = 'ion-cases-inbox';
  // case-window.js's KC_SKIP, which it keeps private. Keep the two in step.
  var SKIP = ['@timestamp', 'message', 'kibana.', 'signal.', 'related.', 'ecs.',
    'agent.id', 'agent.ephemeral_id', 'event.ingested', 'event.created',
    'event.kind', 'event.type', 'event.category', 'event.outcome',
    'event.dataset', 'event.module', 'event.agent_id_status', 'event.original'];
  var KEY_FIELDS = 4;

  var state = { sel: null, owner: '', changed: false, q: '', severity: '', status: '', sort: 'activity', size: '50', shown: 0 };
  var restoring = null;
  var keyfields = {};
  var timer = null;
  var phone = window.matchMedia('(max-width: 767px)');

  function $(id) { return document.getElementById(id); }
  // In an opened case the list still loads, hidden, for the prev/next
  // buttons. It must not overwrite what the inbox will restore.
  function save() { if (window.__initialCaseId) return; try { sessionStorage.setItem(STORE, JSON.stringify(state)); } catch (e) { /* private mode */ } }
  function stored() { try { return JSON.parse(sessionStorage.getItem(STORE) || 'null'); } catch (e) { return null; } }
  function pageMode() { var p = $('case-panel'); return !!(p && p.classList.contains('page-mode')); }
  function rowEls() { return Array.prototype.slice.call(document.querySelectorAll('#cases-board [data-ci-row]')); }
  function typing(t) {
    return !!t && (t.isContentEditable || /^(TEXTAREA|SELECT)$/.test(t.tagName)
      || (t.tagName === 'INPUT' && !/^(checkbox|radio|button)$/.test(t.type)));
  }
  function dialogOpen() {
    return ['closure-modal-overlay', 'create-case-overlay'].some(function (id) {
      var m = $(id); return m && m.style.display === 'flex';
    });
  }

  function readControls() {
    [['filter-search', 'q'], ['filter-severity', 'severity'], ['filter-status', 'status'], ['cases-sort', 'sort'], ['cases-pagesize', 'size']]
      .forEach(function (pair) { var el = $(pair[0]); if (el) state[pair[1]] = el.value; });
  }

  function syncOwnerSelect() {
    var sel = $('filter-assignee');
    if (!sel) return;
    var want = /^\d+$/.test(state.owner) ? state.owner : '';
    if (sel.value !== want && Array.prototype.some.call(sel.options, function (o) { return o.value === want; })) sel.value = want;
  }

  // ── the list ──────────────────────────────────────────────────────────
  function params(p) {
    readControls();
    if (state.owner === 'me') p.set('mine', 'true');
    else if (state.owner === 'none') p.set('unassigned', 'true');
    else if (state.owner) p.set('assigned_to_id', state.owner);
    if (state.changed) p.set('changed', 'true');
    // Coming back from a case: ask for as many rows as were showing, so the
    // selected one is on the page again.
    if (restoring && p.get('offset') === '0' && restoring.shown > Number(p.get('limit'))) {
      p.set('limit', String(Math.min(500, restoring.shown)));
    }
    save();
  }

  function rendered(view, append) {
    if (window.__initialCaseId) return;
    var want = restoring ? restoring.sel : state.sel;
    restoring = null;
    state.shown = view && typeof view.next_offset === 'number' ? view.next_offset : state.shown;
    syncOwnerSelect();
    save();
    if (append) return;
    var rows = rowEls();
    var keep = want != null && rows.some(function (r) { return r.dataset.ciRow === String(want); });
    // A refreshed list can carry a changed case (an assignment, a close),
    // so the preview is read again even when the selection stays.
    if (keep) select(want, { now: true, reload: true });
    else if (rows.length) select(rows[0].dataset.ciRow, { now: true, reload: true });
    else { state.sel = null; save(); clearPreview(); }
  }

  function clearPreview() {
    var pv = $('ci-preview');
    if (!pv) return;
    var p = document.createElement('p');
    p.className = 'ci-mute ci-pv-empty';
    p.textContent = 'Nothing to preview.';
    pv.replaceChildren(p);
  }

  function select(id, opts) {
    opts = opts || {};
    id = String(id);
    var row = $('ci-row-' + id);
    if (!row) return;
    rowEls().forEach(function (r) {
      var on = r === row;
      r.classList.toggle('sel', on);
      r.setAttribute('aria-selected', on ? 'true' : 'false');
      r.tabIndex = on ? 0 : -1;
    });
    if (opts.focus) row.focus({ preventScroll: true });
    row.scrollIntoView({ block: 'nearest' });
    var changed = state.sel !== id;
    state.sel = id;
    save();
    if (opts.sheet && phone.matches) $('ci-inbox').classList.add('sheet-open');
    var shown = document.querySelector('#ci-preview [data-ci-preview]');
    if (!changed && shown && shown.dataset.ciPreview === id && !opts.reload) return;
    clearTimeout(timer);
    timer = setTimeout(function () { loadPreview(id); }, opts.now ? 0 : 120);
  }

  function step(delta) {
    var rows = rowEls();
    if (!rows.length) return;
    var i = rows.findIndex(function (r) { return r.dataset.ciRow === state.sel; });
    var next = i + delta;
    if (next >= rows.length) {
      var more = $('cases-loadmore');
      if (more && !more.hidden && typeof loadMoreCases === 'function') {
        Promise.resolve(loadMoreCases()).then(function () { step(1); });
      }
      return;
    }
    select(rows[Math.max(0, next)].dataset.ciRow, { focus: true });
  }

  // ── the preview ───────────────────────────────────────────────────────
  function loadPreview(id) {
    var pv = $('ci-preview');
    if (!pv || !window.htmx) return;
    pv.setAttribute('hx-sync', 'this:replace');
    pv.classList.add('is-loading');
    window.htmx.ajax('GET', '/ui/cases/' + encodeURIComponent(id) + '/preview', { source: pv, target: pv, swap: 'innerHTML' })
      .then(function () {
        var got = pv.querySelector('[data-ci-preview]');
        if (!got || got.dataset.ciPreview !== state.sel) return;
        pv.classList.remove('is-loading');
        fillPreview(got);
      }, function () {
        if (state.sel !== id) return;
        pv.classList.remove('is-loading');
        var p = document.createElement('p');
        p.className = 'ci-pv-failed';
        p.setAttribute('role', 'alert');
        p.textContent = 'The preview could not be requested.';
        pv.replaceChildren(p);
      });
  }

  function fillPreview(root) {
    var id = root.dataset.ciPreview;
    var owner = root.querySelector('[data-ci-owner]');
    var users = typeof usersCache !== 'undefined' && Array.isArray(usersCache) ? usersCache : [];
    if (owner) {
      users.forEach(function (u) {
        var o = document.createElement('option');
        o.value = String(u.id);
        o.textContent = u.display_name || u.username;
        owner.appendChild(o);
      });
      if (!users.length) owner.disabled = true;
    }
    var box = root.querySelector('[data-ci-keyfields]');
    var ids = JSON.parse(root.dataset.ciAlerts || '[]');
    if (!box || !ids.length) return;
    if (keyfields[id]) { paintKeyfields(box, keyfields[id]); return; }
    var fetchRaw = window.ionAlertDetailFetchRaw;
    if (typeof fetchRaw !== 'function' || !window.ionAlertDetail) {
      box.textContent = 'Key fields are unavailable on this page.';
      return;
    }
    Promise.all(ids.map(function (a) {
      return fetchRaw(a).then(function (raw) { return raw || null; }, function () { return null; });
    })).then(function (docs) {
      keyfields[id] = tally(docs);
      var now = document.querySelector('#ci-preview [data-ci-preview="' + CSS.escape(id) + '"] [data-ci-keyfields]');
      if (now) paintKeyfields(now, keyfields[id]);
    });
  }

  function skip(name) {
    return SKIP.some(function (p) { return name === p || name.indexOf(p) === 0; });
  }

  // The fields most of the read alerts share, as the case window's key
  // context ranks them.
  function tally(docs) {
    var read = docs.filter(Boolean);
    var byKey = {};
    var rows = [];
    read.forEach(function (raw) {
      window.ionAlertDetail.highlightedFields(raw).forEach(function (f) {
        if (skip(f.n)) return;
        var k = f.n + '\u0000' + f.v;
        if (!byKey[k]) { byKey[k] = { n: f.n, v: f.v, c: 0 }; rows.push(byKey[k]); }
        byKey[k].c += 1;
      });
    });
    rows.sort(function (a, b) { return (b.c - a.c) || (a.n < b.n ? -1 : a.n > b.n ? 1 : 0); });
    var seen = {};
    var top = rows.filter(function (r) { if (seen[r.n]) return false; seen[r.n] = true; return true; }).slice(0, KEY_FIELDS);
    return { fields: top, read: read.length, asked: docs.length };
  }

  function paintKeyfields(box, res) {
    box.replaceChildren();
    if (!res.read) {
      box.textContent = 'The alert documents could not be read, so the key fields are unknown.';
      return;
    }
    if (!res.fields.length) {
      box.textContent = 'These alerts have no highlighted fields.';
      return;
    }
    res.fields.forEach(function (f) {
      var s = document.createElement('span');
      s.className = 'ci-kf-f';
      var b = document.createElement('b');
      b.textContent = f.n;
      var v = document.createElement('span');
      v.textContent = f.v;
      s.append(b, v);
      s.title = f.n + ' = ' + f.v;
      box.appendChild(s);
    });
    if (res.read < res.asked) {
      var n = document.createElement('span');
      n.className = 'ci-mute';
      n.textContent = (res.asked - res.read) + ' of ' + res.asked + ' alert documents unread';
      box.appendChild(n);
    }
  }

  function previewButton(action) {
    return document.querySelector('#ci-preview [data-ci-preview="' + CSS.escape(String(state.sel)) + '"] .ci-acts [data-click-action="' + action + '"]');
  }

  function toggleBox(attr, focus) {
    var root = document.querySelector('#ci-preview [data-ci-preview]');
    var box = root && root.querySelector('[' + attr + ']');
    if (!box) return;
    box.hidden = !box.hidden;
    if (!box.hidden) { var f = box.querySelector(focus); if (f) f.focus(); }
  }

  // ── actions (data-click-action) ───────────────────────────────────────
  window.inboxSelect = function (id) { select(id, { sheet: true, focus: true }); };

  window.inboxChip = function (key) {
    var sev = $('filter-severity');
    var st = $('filter-status');
    if (key === 'changed') state.changed = !state.changed;
    else if (key === 'mine' || key === 'unassigned') {
      var v = key === 'mine' ? 'me' : 'none';
      state.owner = state.owner === v ? '' : v;
      var a = $('filter-assignee');
      if (a) a.value = '';
    } else if (key === 'critical' && sev) sev.value = sev.value === 'critical' ? '' : 'critical';
    else if (key === 'closed' && st) st.value = st.value === 'closed' ? '' : 'closed';
    reloadCaseBoard();
  };

  window.inboxClearFilters = function () {
    state.owner = '';
    state.changed = false;
    ['filter-search', 'filter-severity', 'filter-status', 'filter-assignee'].forEach(function (id) { var el = $(id); if (el) el.value = ''; });
    reloadCaseBoard();
  };

  window.inboxAssignMe = function (id) {
    var root = document.querySelector('#ci-preview [data-ci-preview]');
    var me = root ? JSON.parse(root.dataset.ciMe || 'null') : null;
    if (me == null) return;
    panelUpdateField(id, 'assigned_to_id', me);
  };
  window.inboxReassign = function () { toggleBox('data-ci-reassign', 'select'); };
  // The textarea is made here, not sent in the fragment: something sets its
  // style, and htmx copies the attributes of a same-id element across a
  // swap, which CSP refuses as an inline style.
  window.inboxNote = function () {
    var box = document.querySelector('#ci-preview [data-ci-notebox]');
    if (box && !box.querySelector('textarea')) {
      var t = document.createElement('textarea');
      t.id = 'panel-note-input';
      t.rows = 3;
      t.placeholder = box.dataset.ciPlaceholder || '';
      box.prepend(t);
    }
    toggleBox('data-ci-notebox', 'textarea');
  };
  window.inboxCloseSheet = function () { $('ci-inbox').classList.remove('sheet-open'); };

  // ── keys ──────────────────────────────────────────────────────────────
  document.addEventListener('keydown', function (e) {
    if (pageMode() || !$('ci-inbox') || e.ctrlKey || e.metaKey || e.altKey) return;
    if (typing(e.target)) {
      if (e.key === 'Escape' && e.target.blur) e.target.blur();
      return;
    }
    if (dialogOpen()) return;
    var k = e.key;
    var b = null;
    if ((k === 'Enter' || k === ' ') && e.target.closest && e.target.closest('button, a, summary')) return;
    if (k === 'j' || k === 'ArrowDown') step(1);
    else if (k === 'k' || k === 'ArrowUp') step(-1);
    else if (k === 'Enter' && state.sel) openCaseDetail(Number(state.sel));
    else if (k === '/') { var s = $('filter-search'); if (s) s.focus(); }
    else if (k === 'a' || k === 'A') b = previewButton('inboxAssignMe') || previewButton('inboxReassign');
    else if (k === 'n' || k === 'N') b = previewButton('inboxNote');
    else if (k === 'c' || k === 'C') b = previewButton('panelUpdateField');
    else if (k === 'Escape') window.inboxCloseSheet();
    else return;
    e.preventDefault();
    if (b) b.click();
  });

  document.addEventListener('dblclick', function (e) {
    var row = e.target.closest && e.target.closest('#cases-board [data-ci-row]');
    if (row && !pageMode()) openCaseDetail(Number(row.dataset.ciRow));
  });

  // Ahead of the delegated reloadCaseBoard, which reads params() at once.
  document.addEventListener('change', function (e) {
    if (e.target && e.target.id === 'filter-assignee') state.owner = e.target.value;
  }, true);

  document.addEventListener('htmx:afterSettle', syncOwnerSelect);

  // In an opened case, Esc goes back to the list once the case window has
  // nothing of its own to clear (its picks, its find, its pill list). Capture
  // phase, so the check sees that state before case-window.js clears it.
  window.addEventListener('keydown', function (e) {
    if (e.key !== 'Escape' || !pageMode() || e.ctrlKey || e.metaKey || e.altKey) return;
    if (typing(e.target) || dialogOpen()) return;
    var s = window.ionCaseWindow && window.ionCaseWindow.state;
    if (s && ((s.picks && s.picks.size) || s.find)) return;
    var pills = document.querySelector('[data-cwin-pill-list]');
    if (pills && !pills.hidden) return;
    if (document.querySelector('dialog[open]')) return;
    e.preventDefault();
    e.stopPropagation();
    closeCasePanel();
  }, true);

  // ── coming back ───────────────────────────────────────────────────────
  document.addEventListener('DOMContentLoaded', function () {
    var saved = stored();
    if (!saved || !$('ci-inbox')) return;
    Object.keys(state).forEach(function (k) { if (saved[k] != null) state[k] = saved[k]; });
    [['filter-search', 'q'], ['filter-severity', 'severity'], ['filter-status', 'status'], ['cases-sort', 'sort'], ['cases-pagesize', 'size']]
      .forEach(function (pair) {
        var el = $(pair[0]);
        if (el && state[pair[1]] != null && (el.tagName !== 'SELECT' || Array.prototype.some.call(el.options, function (o) { return o.value === String(state[pair[1]]); }))) el.value = state[pair[1]];
      });
    if (typeof boardSort !== 'undefined') boardSort = $('cases-sort').value;
    if (typeof boardPageSize !== 'undefined') boardPageSize = parseInt($('cases-pagesize').value, 10);
    // In an opened case the same filters order the prev/next buttons.
    if (!window.__initialCaseId) restoring = { sel: state.sel, shown: Number(state.shown) || 0 };
  });

  window.ionCasesInbox = { params: params, rendered: rendered, select: select, get state() { return state; } };
})();
