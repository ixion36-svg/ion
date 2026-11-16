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
