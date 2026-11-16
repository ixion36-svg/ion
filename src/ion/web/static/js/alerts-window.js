/* The alert window on /alerts: the inset workspace panel an alert opens in,
 * its address, and prev/next through the queue.
 *
 * It owns the panel chrome and nothing about an alert's content, which
 * static/js/alert-detail.js renders into #alert-detail-body for this page
 * and for /cases alike. The page passes in what it knows (the filtered
 * queue, which alert is open, how to open another) the way it does for
 * alerts-queue.js, so this file reads no page globals.
 *
 * Two modes, one panel:
 *   overlay  opened from the queue. The queue stays loaded behind it, so
 *            the filters and the bulk selection are still there on close.
 *            The address becomes /alerts/{id} while it is open.
 *   page     the server rendered /alerts/{id}. The panel sits in the
 *            document flow and closing goes to /alerts.
 */
(function () {
  'use strict';

  var host = null;
  var arranger = null;

  // The alert's sections, arranged the way the case window's are: movable
  // between columns, foldable, hideable, one arrangement remembered for every
  // alert. Triage is the two columns the window always had, working material
  // beside context; the left column exists for an analyst with the width to
  // use it and gives its space back while it is empty.
  var WORKING = { fields: 1, guide: 1, rawdata: 1, autoinvestigate: 1 };
  var COLUMNS = {
    left: 'minmax(260px,1fr)', centre: 'minmax(0,1.5fr)', right: 'minmax(260px,1fr)', full: null
  };
  var PRESETS = [
    { id: 'triage', label: 'Triage', col: null },
    { id: 'wide', label: 'Wide', col: function (key) {
        if (key === 'autoinvestigate' || key === 'guide') return 'left';
        return WORKING[key] ? 'centre' : 'right';
    } },
    { id: 'focus', label: 'Focus', col: function () { return 'centre'; } }
  ];

  // A hidden section's jump link would scroll to nothing.
  function syncJumpLinks() {
    var body = el('alert-detail-body');
    Array.prototype.forEach.call(body.querySelectorAll('.iad-jump-link'), function (link) {
      var sec = el('iad-sec-' + link.dataset.section);
      link.hidden = !!sec && sec.hidden;
    });
  }

  function arrangeSections() {
    var body = el('alert-detail-body');
    if (!arranger) {
      var tools = panel().querySelector('.aw-tools');
      arranger = window.ionArrange.create({
        body: body,
        candidates: '.iad-section',
        storageKey: 'ion-alert-window-layout-v1',
        columns: COLUMNS,
        defaultCol: function (key) { return WORKING[key] ? 'centre' : 'right'; },
        presets: PRESETS,
        keyFor: function (sec) { return sec.id.replace('iad-sec-', ''); },
        titleOf: function (sec) { return sec.querySelector('.iad-section-title'); },
        headOf: function (sec) { return sec.querySelector('.iad-sec-head'); },
        collapsedClass: 'iad-folded',
        defaultCollapsed: function (key) { return key === 'rawdata'; },
        toolsHost: tools,
        toolsBefore: tools.querySelector('.ion-ws-close'),
        onChange: syncJumpLinks
      });
    }
    // The component rendered its two fixed columns; the sections leave them
    // for the grid, and the emptied wrapper goes.
    var fixed = body.querySelector('.iad-cols');
    arranger.apply();
    if (fixed) fixed.remove();
  }

  // ── the rail ──────────────────────────────────────────────────────────
  // The alerts the analyst ticked in the queue, beside the open one: the
  // set they chose to work through, not the whole queue. With nothing ticked
  // there is no rail and the alert has the window. A selection can be the
  // whole queue (500), so the rail shows the ones around the open alert and
  // says how many it left out on each side.
  var RAIL_REACH = 40;
  var RAIL_KEY = 'ion-alert-window-rail';
  var SEVERITIES = { critical: 1, high: 1, medium: 1, low: 1, info: 1 };

  function clone(id) {
    return el(id).content.firstElementChild.cloneNode(true);
  }

  function railWanted() {
    try { return localStorage.getItem(RAIL_KEY) !== '0'; } catch (_) { return true; }
  }

  function railNote(count, where) {
    var note = clone('aw-rail-more');
    note.textContent = count + ' ' + where + ' selected';
    return note;
  }

  function railItem(alert, selected) {
    var item = clone('aw-rail-item');
    item.dataset.args = JSON.stringify([alert.id]);
    var severity = String(alert.severity || '').toLowerCase();
    item.querySelector('.rail-sev').classList.add('rail-sev-' + (SEVERITIES[severity] ? severity : 'info'));
    item.querySelector('.ion-ws-rail-item-name').textContent = alert.title || alert.rule_name || alert.id;
    var when = alert.timestamp ? new Date(alert.timestamp) : null;
    var parts = [alert.host, alert.user,
      when && !isNaN(when) ? when.toLocaleString(undefined, { month: 'short', day: 'numeric', hour: '2-digit', minute: '2-digit' }) : null];
    item.querySelector('.ion-ws-rail-item-sub').textContent = parts.filter(Boolean).join(' \u00b7 ');
    if (selected) {
      item.classList.add('selected');
      item.setAttribute('aria-current', 'true');
    }
    return item;
  }

  function renderRail(pos) {
    var rail = el('alert-window-rail');
    var list = pos.selected;
    var shown = railWanted() && list.length > 0;
    el('alert-window-grid').classList.toggle('aw-no-rail', !shown);
    rail.hidden = !shown;
    var toggle = el('alert-window-rail-toggle');
    toggle.setAttribute('aria-pressed', railWanted() ? 'true' : 'false');
    toggle.disabled = list.length === 0;
    toggle.title = list.length === 0
      ? 'Tick alerts in the queue to list them beside the one you open'
      : 'Show or hide the selected alerts beside this one';
    if (!shown) { rail.replaceChildren(); return; }

    var centre = pos.selectedIndex === -1 ? 0 : pos.selectedIndex;
    var from = Math.max(0, centre - RAIL_REACH);
    var to = Math.min(list.length, centre + RAIL_REACH + 1);
    var nodes = [];
    var heading = clone('aw-rail-heading');
    heading.textContent = 'Selected \u00b7 ' + list.length;
    nodes.push(heading);
    if (from > 0) nodes.push(railNote(from, 'earlier'));
    var current = null;
    for (var i = from; i < to; i++) {
      var item = railItem(list[i], i === pos.selectedIndex);
      if (i === pos.selectedIndex) current = item;
      nodes.push(item);
    }
    if (to < list.length) nodes.push(railNote(list.length - to, 'later'));
    rail.replaceChildren.apply(rail, nodes);
    if (current) current.scrollIntoView({ block: 'nearest' });
  }

  function toggleRail() {
    try { localStorage.setItem(RAIL_KEY, railWanted() ? '0' : '1'); } catch (_) { /* blocked */ }
    renderRail(position());
  }

  function el(id) { return document.getElementById(id); }
  function panel() { return el('alert-window'); }

  function isOpen() {
    var p = panel();
    return !!p && p.classList.contains('open');
  }

  function isPageMode() {
    var p = panel();
    return !!p && p.classList.contains('page-mode');
  }

  function setAddress(path) {
    if (window.history && window.history.replaceState && window.location.pathname !== path) {
      window.history.replaceState(null, '', path + (path === '/alerts' ? window.location.search : ''));
    }
  }

  function indexOfAlert(list, id) {
    for (var i = 0; i < list.length; i++) {
      if (list[i].id === id) return i;
    }
    return -1;
  }

  // Where the open alert sits. Prev/next step through the selection when the
  // open alert is one of the ticked ones, so the rail and the arrows walk the
  // same list; otherwise through the queue as the table shows it.
  function position() {
    var queue = host ? host.getAlerts() : [];
    var selected = host ? host.getSelected() : [];
    var id = host ? host.currentId() : null;
    var selectedIndex = indexOfAlert(selected, id);
    var scoped = selectedIndex !== -1;
    return {
      list: scoped ? selected : queue,
      index: scoped ? selectedIndex : indexOfAlert(queue, id),
      scoped: scoped,
      selected: selected,
      selectedIndex: selectedIndex
    };
  }

  // The queue can be re-read or re-filtered under an open alert, so the
  // position is recomputed from the list each time instead of remembered.
  function refreshNav() {
    if (!isOpen()) return;
    var pos = position();
    var label = el('alert-window-position');
    var prev = el('alert-window-prev');
    var next = el('alert-window-next');
    var inQueue = pos.index !== -1;
    if (label) {
      label.textContent = inQueue
        ? 'Alert ' + (pos.index + 1) + ' of ' + pos.list.length + (pos.scoped ? ' selected' : '')
        : 'Alert · not in the queue as filtered';
    }
    if (prev) prev.disabled = !inQueue || pos.index === 0;
    if (next) next.disabled = !inQueue || pos.index === pos.list.length - 1;
    renderRail(pos);
  }

  function open() {
    var p = panel();
    p.classList.add('open');
    if (!isPageMode()) el('alert-window-overlay').classList.add('open');
  }

  function show(alert) {
    el('alert-detail-title').textContent = alert.title || alert.rule_name || alert.id;
    arrangeSections();
    open();
    setAddress('/alerts/' + encodeURIComponent(alert.id));
    el('alert-detail-body').scrollTop = 0;
    refreshNav();
  }

  // An alert that could not be read still opens the window, to say so.
  function fail(message) {
    el('alert-detail-title').textContent = 'Alert unavailable';
    var note = document.createElement('p');
    note.className = 'aw-unavailable';
    note.setAttribute('role', 'alert');
    note.textContent = message;
    el('alert-detail-body').replaceChildren(note);
    open();
    el('alert-window-position').textContent = 'Alert';
    el('alert-window-prev').disabled = true;
    el('alert-window-next').disabled = true;
    renderRail({ selected: [], selectedIndex: -1 });
  }

  function hide() {
    if (!isOpen()) return;
    if (isPageMode()) {
      window.location.assign('/alerts');
      return;
    }
    panel().classList.remove('open');
    el('alert-window-overlay').classList.remove('open');
    setAddress('/alerts');
  }

  function step(delta) {
    var pos = position();
    if (pos.index === -1) return;
    var target = pos.list[pos.index + delta];
    if (target) host.open(target.id);
  }

  function mount(h) { host = h; }

  window.ionAlertWindow = {
    mount: mount, show: show, hide: hide, fail: fail,
    isOpen: isOpen, refreshNav: refreshNav, step: step
  };
  window.alertWindowStep = step;
  window.alertWindowToggleRail = toggleRail;
})();
