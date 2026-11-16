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

  function position() {
    var list = host ? host.getAlerts() : [];
    var id = host ? host.currentId() : null;
    var index = -1;
    for (var i = 0; i < list.length; i++) {
      if (list[i].id === id) { index = i; break; }
    }
    return { list: list, index: index };
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
        ? 'Alert ' + (pos.index + 1) + ' of ' + pos.list.length
        : 'Alert · not in the queue as filtered';
    }
    if (prev) prev.disabled = !inQueue || pos.index === 0;
    if (next) next.disabled = !inQueue || pos.index === pos.list.length - 1;
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
})();
