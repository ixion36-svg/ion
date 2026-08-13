/**
 * ION - shared alert-detail component
 * =============================================================================
 * ONE renderer for an alert, used by BOTH /alerts and /cases.
 *
 * Before this existed, /cases showed a compact subset of an alert (common
 * fields, observables, a Bob meter) behind three separate accordions, while
 * /alerts showed the full picture behind eight tabs. An analyst had to leave
 * the case to see the alert properly. Worse, flattenAlertFields,
 * _alertFieldsTable and toggleAllAlertFields had already been copy-pasted into
 * both templates and the copies had begun to drift (class names, esc vs
 * escapeHtml), so fixing an alert-rendering bug meant remembering to fix it
 * twice.
 *
 * -- The one real design decision -------------------------------------------
 * Both pages want the SAME sections in DIFFERENT arrangements:
 *
 *   layout: 'tabs'     /alerts - eight tabs, one visible at a time. Unchanged.
 *   layout: 'stacked'  /cases  - every section stacked in one scroll with
 *                                sticky jump-links. Nothing is hidden, so
 *                                seeing an alert fully costs ONE click instead
 *                                of eight.
 *
 * SECTIONS below is the single source of truth for both. Add a section once and
 * both pages get it, each in its own arrangement.
 *
 * -- Contract ----------------------------------------------------------------
 *   ionAlertDetail.render(alert, opts) -> html string
 *   ionAlertDetail.mount(container, alert, opts)  render + wire lazy loaders
 *   ionAlertDetail.showSection(name)              programmatic navigation
 *
 *   opts = {
 *     layout:        'tabs' | 'stacked'   (default 'tabs')
 *     aiAvailable:   bool                 show AI Analyze / Discuss
 *     arkimeEnabled: bool                 show the Arkime PCAP link
 *     classPrefix:   'alert-parsed' | 'cpanel-alert'
 *     caseId:        number|null          enables "add fields as evidence"
 *   }
 *
 * Host page must provide (both already do, via static/js/app.js):
 *   escapeHtml(), showToast()
 *
 * CSP: served as a static script, so there are no inline handlers - every
 * control uses data-click-action and the delegation helper.
 */
(function () {
  'use strict';

  // Section order + labels - the single source of truth for BOTH layouts.
  var SECTIONS = [
    { id: 'related',         label: 'Related Alerts' },
    { id: 'timeline',        label: 'Timeline' },
    { id: 'comments',        label: 'Comments' },
    { id: 'case',            label: 'Case' },
    { id: 'sequence',        label: 'Sequence' },
    { id: 'autoinvestigate', label: '\uD83D\uDD0D Auto-Investigate' },
    { id: 'fields',          label: 'Fields' },
    { id: 'rawdata',         label: 'Raw Data' }
  ];

  var _current = null;
  var _opts = {};
  // Related + Timeline share ONE /related request; this stops the two tabs
  // issuing it twice.
  var _relatedLoaded = false;
  // Captured at render time so "add fields as evidence" can post without
  // re-parsing. Written and read only in this file.
  var _alertParsedKeyFields = [];

  // The two page copies differed ONLY in these class names. Parameterising is
  // what let the two functions become one.
  function _cls(suffix) {
    var p = _opts.classPrefix || 'alert-parsed';
    if (suffix === 'fields-table') return p + '-fields-table';
    if (suffix === 'key')          return p === 'alert-parsed' ? 'apf-key' : 'caf-key';
    if (suffix === 'val')          return p === 'alert-parsed' ? 'apf-val' : 'caf-val';
    if (suffix === 'showall')      return p + '-showall';
    return p + '-' + suffix;
  }

  // Both host pages load static/js/app.js, which defines these globally.
  function escapeHtml(s) { return window.escapeHtml ? window.escapeHtml(s) : String(s == null ? '' : s); }
  function showToast(m, k) { if (window.showToast) window.showToast(m, k); }

  // ── host adapter ─────────────────────────────────────────────────────────
  // These helpers are declared only in alerts.html, so a bare reference throws
  // on any other host page. Prefer the page's version where it exists, else use
  // the local fallback. try/catch rather than `window.X` because top-level
  // let/const never land on window, and a string typeof would need eval.
  function _page(probe) { try { return probe(); } catch (e) { return null; } }
  function _pageTriageCache()   { return _page(function () { return triageCache; }); }
  function _pageSimilarity()    { return _page(function () { return calculateSimilarity; }); }
  function _pageExtractedBlock(){ return _page(function () { return _alertExtractedValuesBlock; }); }
  function _pageTimeline()      { return _page(function () { return renderTimeline; }); }
  function _pageAlertPayload()  { return _page(function () { return getAlertPayload; }); }
  function _pageAIContent()     { return _page(function () { return formatAIContent; }); }
  function _pageNotify()        { return _page(function () { return showNotification; }); }
  function _pageFormatDate()    { return _page(function () { return formatDate; }); }

  function _notify(msg, kind) {
    var fn = _pageNotify();
    if (fn) { fn(msg, kind); return; }
    showToast(msg, kind);
  }

  function _fmtDate(ts) {
    var fn = _pageFormatDate();
    if (fn) return fn(ts);
    return ts ? new Date(ts).toLocaleString() : '-';
  }

  function _triageFor(alertId) {
    var c = _pageTriageCache();
    return (c && c[alertId]) || null;
  }

  // Field allowlist for the well-known-fields table; owned here so the section
  // works on a host that has no such list.
  var _KEY_PREFIXES = [
    '@timestamp', 'message',
    'rule.name', 'rule.description',
    'event.action', 'event.category', 'event.outcome', 'event.severity',
    'event.kind', 'event.type', 'event.reason',
    'kibana.alert.severity', 'kibana.alert.workflow_status',
    'kibana.alert.rule.name', 'kibana.alert.reason', 'kibana.alert.risk_score',
    'host.name', 'host.hostname', 'host.ip', 'host.os',
    'user.', 'source.', 'destination.', 'client.', 'server.',
    'process.', 'file.', 'url.', 'dns.', 'network.', 'tls.', 'http.',
    'registry.', 'email.', 'threat.', 'observer.', 'related.', 'winlog.event_data.'
  ];
  function _keyPrefixes() {
    return _page(function () { return ALERT_KEY_PREFIXES; }) || _KEY_PREFIXES;
  }

  var _VERDICT_CLASS = {
    true_positive: 'autoinv-v-tp', false_positive: 'autoinv-v-fp',
    benign_true_positive: 'autoinv-v-btp', inconclusive: 'autoinv-v-inc'
  };
  function _verdictClass(v) {
    var m = _page(function () { return _AUTOINV_VERDICT_CLASS; }) || _VERDICT_CLASS;
    return m[v] || 'autoinv-v-inc';
  }
  function _refBadges(refs) {
    var fn = _page(function () { return _autoinvRefBadges; });
    if (fn) return fn(refs);
    if (!refs || !refs.length) return '';
    return ' ' + refs.map(function (r) {
      return '<span class="autoinv-ref">' + escapeHtml(String(r)) + '</span>';
    }).join(' ');
  }

  // On /cases the alert row already carries these, so no triage cache is needed.
  function _extractedObs(alertId) {
    var t = _triageFor(alertId);
    if (t && t.observables && t.observables.length) return t.observables;
    if (_current && _current.id === alertId && Array.isArray(_current.observables)) {
      return _current.observables;
    }
    return [];
  }

  function _extractedValuesBlock(alertId) {
    var host = _pageExtractedBlock();
    if (host) return host(alertId);
    var obs = _extractedObs(alertId);
    if (!obs.length) return '';
    var h = '<div class="alert-parsed-extracted">'
          + '<div class="alert-parsed-extracted-title">Extracted values (' + obs.length + ')</div>'
          + '<table class="alert-parsed-fields-table"><tbody>';
    obs.forEach(function (o) {
      if (!o) return;
      h += '<tr><td class="apf-key">' + escapeHtml(String(o.type || 'unknown')) + '</td>'
         + '<td class="apf-val">' + escapeHtml(String(o.value || '')) + '</td></tr>';
    });
    return h + '</tbody></table></div>';
  }

  function _similarity(a, b, primary) {
    var host = _pageSimilarity();
    if (host) return host(a, b, primary);
    if (!a || !b) return { score: 0, level: 'low', reasons: [] };
    var score = 0, reasons = [];
    function add(n, why) { score += n; reasons.push(why); }
    if (primary === 'host' && a.host === b.host) add(30, 'Same host');
    if (primary === 'user' && a.user === b.user) add(30, 'Same user');
    if (primary === 'rule' && a.rule_name === b.rule_name) add(40, 'Same rule');
    if (primary !== 'host' && a.host && a.host === b.host) add(20, 'Same host');
    if (primary !== 'user' && a.user && a.user === b.user) add(15, 'Same user');
    if (primary !== 'rule' && a.rule_name && a.rule_name === b.rule_name) add(25, 'Same rule');
    if (a.severity === b.severity) add(10, 'Same severity');
    if (a.mitre_technique_id && a.mitre_technique_id === b.mitre_technique_id) add(15, 'Same MITRE technique');
    if (Math.abs(new Date(a.timestamp).getTime() - new Date(b.timestamp).getTime()) < 3600000) {
      add(10, 'Within 1 hour');
    }
    score = Math.min(score, 100);
    return { score: score, level: score >= 70 ? 'high' : score >= 40 ? 'medium' : 'low', reasons: reasons };
  }

  function _timelineInto(container, alerts) {
    var host = _pageTimeline();
    if (host) return host(container, alerts);
    if (!container) return;
    if (!alerts || !alerts.length) {
      container.innerHTML = '<div class="empty-state">No timeline data</div>';
      return;
    }
    var h = '<div class="timeline">';
    alerts.forEach(function (a) {
      h += '<div class="timeline-item' + (a._isCurrent ? ' current' : '') + ' severity-' + escapeHtml(String(a.severity || '')) + '">'
         + '<div class="timeline-time">' + escapeHtml(_fmtDate(a.timestamp)) + '</div>'
         + '<div class="timeline-content">'
         + '<span class="severity-badge severity-' + escapeHtml(String(a.severity || '')) + '">'
         + escapeHtml(String(a.severity || '')) + '</span> '
         + '<span class="timeline-title">' + escapeHtml(String(a.title || a.rule_name || '')) + '</span>'
         + '</div></div>';
    });
    container.innerHTML = h + '</div>';
  }

  function _alertPayload(alertId) {
    var host = _pageAlertPayload();
    if (host) return host(alertId);
    if (!_current || _current.id !== alertId) return null;
    var t = _triageFor(alertId) || {};
    return {
      id: _current.id, rule_name: _current.rule_name, severity: _current.severity,
      host: _current.host, user: _current.user, message: _current.message,
      timestamp: _current.timestamp, status: t.status, priority: t.priority
    };
  }

  function _aiContent(text) {
    var fn = _pageAIContent();
    return fn ? fn(text) : String(text == null ? '' : text);
  }

  function renderSystemBadge(a) {
      if (!a.source_system && !a.cyab_system_name && !a.tide_system_name) {
          return '<span class="_ion-s-b8e0b1fa55">-</span>';
      }
      const cyabName = a.cyab_system_name;
      const tideName = a.tide_system_name;
      const ns = a.source_system || '';
      const display = cyabName || tideName || ns;
      const tooltipParts = [];
      if (ns) tooltipParts.push(`namespace: ${ns}`);
      if (cyabName) tooltipParts.push(`CyAB: ${cyabName}`);
      if (tideName && tideName !== cyabName) tooltipParts.push(`TIDE: ${tideName}`);
      const tooltip = escapeHtml(tooltipParts.join(' • ') || display);
      if (a.cyab_system_id) {
          return `<a href="/cyab#${a.cyab_system_id}" class="system-badge linked" title="${tooltip}" data-stop-propagation>${escapeHtml(display)}</a>`;
      }
      return `<span class="system-badge" title="${tooltip}">${escapeHtml(display)}</span>`;
  }

  function syntaxHighlightJSON(obj) {
      if (!obj) return '<span class="json-null">null</span>';
      const json = JSON.stringify(obj, null, 2);
      return json.replace(/("(\\u[a-zA-Z0-9]{4}|\\[^u]|[^\\"])*"(\s*:)?|\b(true|false|null)\b|-?\d+(?:\.\d*)?(?:[eE][+\-]?\d+)?)/g, function(match) {
          let cls = 'json-number';
          if (/^"/.test(match)) {
              if (/:$/.test(match)) {
                  cls = 'json-key';
              } else {
                  cls = 'json-string';
              }
          } else if (/true|false/.test(match)) {
              cls = 'json-boolean';
          } else if (/null/.test(match)) {
              cls = 'json-null';
          }
          return `<span class="${cls}">${escapeHtml(match)}</span>`;
      });
  }

  function flattenAlertFields(obj, prefix, out) {
      out = out || {};
      prefix = prefix || '';
      if (obj && typeof obj === 'object' && !Array.isArray(obj)) {
          for (const k of Object.keys(obj)) {
              flattenAlertFields(obj[k], prefix ? prefix + '.' + k : k, out);
          }
      } else if (Array.isArray(obj)) {
          if (obj.every(x => x === null || typeof x !== 'object')) {
              if (obj.length) out[prefix] = obj.join(', ');
          } else {
              obj.forEach((x, i) => flattenAlertFields(x, prefix + '[' + i + ']', out));
          }
      } else if (obj !== null && obj !== undefined && obj !== '') {
          out[prefix] = obj;
      }
      return out;
  }

  function _alertFieldsTable(flat, keys) {
      let h = '<table class="' + _cls('fields-table') + '"><tbody>';
      for (const k of keys) {
          h += '<tr><td class="' + _cls('key') + '">' + escapeHtml(k) + '</td>'
             + '<td class="' + _cls('val') + '">' + escapeHtml(String(flat[k])) + '</td></tr>';
      }
      return h + '</tbody></table>';
  }

  function renderAlertParsedFields(alertId, raw) {
      const extracted = _extractedValuesBlock(alertId);
      const flat = flattenAlertFields(raw);
      const allKeys = Object.keys(flat).sort();
      if (!allKeys.length) {
          return extracted || '<div class="alert-parsed-empty">No fields available for this alert.</div>';
      }
      const isKey = k => _keyPrefixes().some(p => k === p || k.startsWith(p));
      let keyKeys = allKeys.filter(isKey);
      let otherKeys = allKeys.filter(k => !isKey(k));
      // Fallback: a non-ECS alert that matches nothing should still show its data.
      if (!keyKeys.length) { keyKeys = allKeys; otherKeys = []; }
      _alertParsedKeyFields = keyKeys.map(k => ({ key: k, value: String(flat[k]) }));
      let h = extracted + _alertFieldsTable(flat, keyKeys);
      if (otherKeys.length) {
          const allId = 'alert-parsed-all';
          const moreLabel = 'Show all ' + allKeys.length + ' fields (' + otherKeys.length + ' more)';
          h += '<button type="button" class="alert-parsed-showall" '
             + 'data-click-action="toggleAllAlertFields" data-args=\'["' + allId + '"]\' '
             + 'data-more-label="' + escapeHtml(moreLabel) + '" data-less-label="Show fewer fields" '
             + 'aria-expanded="false">' + escapeHtml(moreLabel) + '</button>';
          h += '<div class="alert-parsed-fields-all" id="' + allId + '" hidden>'
             + _alertFieldsTable(flat, otherKeys) + '</div>';
      }
      // Offer the evidence-note action only when this alert is linked to a case.
      const caseId = (_triageFor(alertId) || {}).case_id;
      if (caseId) {
          h += '<button type="button" class="alert-parsed-evidence" '
             + 'data-click-action="addAlertFieldsAsEvidence" data-args=\'["' + escapeHtml(String(caseId)) + '"]\'>'
             + '&#128278; Add fields as evidence note</button>';
      }
      return h;
  }

  function toggleAllAlertFields(allId) {
      const el = document.getElementById(allId);
      if (!el) return;
      const btn = (this && this.classList && this.classList.contains(_cls('showall'))) ? this : null;
      if (el.hasAttribute('hidden')) {
          el.removeAttribute('hidden');
          if (btn) { btn.textContent = btn.dataset.lessLabel || 'Show fewer fields'; btn.setAttribute('aria-expanded', 'true'); }
      } else {
          el.setAttribute('hidden', '');
          if (btn) { btn.textContent = btn.dataset.moreLabel || 'Show all fields'; btn.setAttribute('aria-expanded', 'false'); }
      }
  }

  async function addAlertFieldsAsEvidence(caseId) {
      if (!caseId) { showToast('This alert is not linked to a case', 'warning'); return; }
      const alertId = _current ? _current.id : null;
      const obs = alertId ? _extractedObs(alertId) : [];
      const fields = _alertParsedKeyFields || [];
      if (!fields.length && !obs.length) { showToast('No fields to add', 'warning'); return; }
      const lines = ['**Alert fields (evidence)**', ''];
      if (obs.length) {
          lines.push('_Extracted values:_');
          for (const o of obs) lines.push('- `' + (o.type || 'unknown') + '` = ' + (o.value || ''));
          lines.push('');
      }
      if (fields.length) {
          lines.push('_Well-known fields:_');
          for (const f of fields) lines.push('- **' + f.key + '**: ' + f.value);
      }
      try {
          const resp = await fetch('/api/cases/' + encodeURIComponent(caseId) + '/notes', {
              method: 'POST',
              headers: { 'Content-Type': 'application/json' },
              body: JSON.stringify({ content: lines.join('\n') }),
          });
          if (!resp.ok) {
              const d = await resp.json().catch(() => ({}));
              throw new Error(d.detail || ('HTTP ' + resp.status));
          }
          showToast('Fields added to the case as an evidence note', 'success');
      } catch (e) {
          showToast('Failed to add evidence note: ' + e.message, 'error');
      }
  }

  // ── coalesced raw fetch ───────────────────────────────────────
  //
  // The stacked layout opens every section at once, and THREE of them want the
  // same `/raw` document: the Fields section, the Raw Data section, and (on
  // /cases) the rule guide. They start together, so each one checks
  // `_current.raw_data`, finds it empty, and issues its own request — the same
  // Elasticsearch fetch three times per alert click. Under tabs only the
  // visible section loaded, so v0.77.0 turned one request into three and put
  // them on the critical path of every selection.
  //
  // One promise per alert id, shared by every caller. Cleared on failure so a
  // transient error is retryable, and keyed by id so switching alerts does not
  // serve the previous alert's document.
  var _rawInflight = {};

  function fetchRawOnce(alertId) {
      if (_current && _current.id === alertId && _current.raw_data) {
          return Promise.resolve(_current.raw_data);
      }
      if (_rawInflight[alertId]) return _rawInflight[alertId];

      _rawInflight[alertId] = fetch(
          '/api/elasticsearch/alerts/' + encodeURIComponent(alertId) + '/raw'
      ).then(function (r) {
          return r.json().catch(function () { return {}; });
      }).then(function (data) {
          var raw = data && data.raw_data;
          if (raw && _current && _current.id === alertId) _current.raw_data = raw;
          // Keep the resolved promise cached: re-selecting an alert in the rail
          // should not re-hit Elasticsearch.
          return raw || null;
      }).catch(function (e) {
          delete _rawInflight[alertId];
          throw e;
      });
      return _rawInflight[alertId];
  }
  window.ionAlertDetailFetchRaw = fetchRawOnce;

  async function loadAlertParsedFields(alertId, container) {
      if (_current && _current.raw_data) {
          container.innerHTML = renderAlertParsedFields(alertId, _current.raw_data);
          return;
      }
      container.innerHTML = '<div class="loading">Loading fields...</div>';
      try {
          const raw = await fetchRawOnce(alertId);
          const data = { raw_data: raw };
          const r = { ok: !!raw };
          if (!r.ok || !data.raw_data) {
              // Still surface extracted values even when the raw _source is gone.
              container.innerHTML = _extractedValuesBlock(alertId)
                  || '<div class="alert-parsed-empty">No raw data available for this alert.</div>';
              return;
          }
          if (_current && _current.id === alertId) {
              _current.raw_data = data.raw_data;
          }
          container.innerHTML = renderAlertParsedFields(alertId, data.raw_data);
      } catch (e) {
          container.innerHTML = _extractedValuesBlock(alertId)
              + '<div class="alert-parsed-empty">Failed to load fields: '
              + escapeHtml(String((e && e.message) || e)) + '</div>';
      }
  }

  // Comments arrive on GET /triage as {triage, comments}; /comments is
  // POST-only. One GET, on first click.
  var _commentsLoaded = false;

  function _renderComments(alertId, comments) {
    var host = _page(function () { return renderCommentsTab; });
    if (host) { host(alertId, comments); return; }        // /alerts: richer, markdown + translate
    var el = document.getElementById('detail-tab-comments');
    if (!el) return;
    var h = '<div class="comments-list">';
    if (!comments || !comments.length) {
      h += '<div class="empty-state">No comments yet</div>';
    } else {
      comments.forEach(function (c) {
        h += '<div class="comment-item">'
           + '<div class="comment-header">'
           +   '<span class="comment-user">' + escapeHtml(String(c.user || 'Unknown')) + '</span>'
           +   '<span class="comment-time">' + escapeHtml(_fmtDate(c.created_at)) + '</span>'
           + '</div>'
           + '<div class="comment-body">' + escapeHtml(String(c.content || '')) + '</div>'
           + '</div>';
      });
    }
    h += '</div>'
       + '<div class="comment-form">'
       +   '<textarea id="comment-input" placeholder="Add a comment..."></textarea>'
       +   '<button class="btn btn-primary" data-click-action="ionAlertAddComment" '
       +     'data-args=\'["' + escapeHtml(String(alertId)) + '"]\'>Submit</button>'
       + '</div>';
    el.innerHTML = h;
  }

  function loadAlertComments(alertId) {
    var el = document.getElementById('detail-tab-comments');
    if (!el) return;
    fetch('/api/elasticsearch/alerts/' + encodeURIComponent(alertId) + '/triage')
      .then(function (r) { return r.json(); })
      .then(function (data) { _renderComments(alertId, (data && data.comments) || []); })
      .catch(function () {
        el.innerHTML = '<div class="error">Failed to load comments</div>';
      });
  }

  // Distinct name: alerts.html has its own top-level addComment().
  function ionAlertAddComment(alertId) {
    var input = document.getElementById('comment-input');
    var content = input && input.value.trim();
    if (!content) return;
    fetch('/api/elasticsearch/alerts/' + encodeURIComponent(alertId) + '/comments', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ content: content })
    }).then(function (r) {
      if (!r.ok) throw new Error('HTTP ' + r.status);
      if (input) input.value = '';
      loadAlertComments(alertId);
    }).catch(function () { _notify('Failed to add comment', 'error'); });
  }

  function renderRelatedSection(title, alerts, matchType) {
      const currentCase = _current && (_triageFor(_current.id) || {}).case_id;

      return `
          <div class="related-section">
              <div class="related-section-header">
                  <h4>${title} (${alerts.length})</h4>
                  ${currentCase ? `<button class="btn btn-sm btn-secondary" data-click-action="linkAllToCase" data-args='["${matchType}", ${currentCase}]'>Link all to case</button>` : ''}
              </div>
              ${alerts.slice(0, 10).map(a => {
                  const triage = _triageFor(a.id);
                  const inSameCase = triage && currentCase && triage.case_id === currentCase;
                  const hasCase = triage && triage.case_id;
                  const similarity = _similarity(_current, a, matchType);

                  return `
                  <div class="related-alert-item ${inSameCase ? 'same-case' : ''}">
                      <div class="related-alert-main" data-click-action="showAlertDetail" data-args='["${escapeHtml(a.id)}"]'>
                          <span class="severity-badge severity-${a.severity}">${a.severity}</span>
                          <span class="similarity-badge similarity-${similarity.level}" title="${similarity.reasons.join(', ')}">${similarity.score}%</span>
                          <span class="related-alert-title" title="${escapeHtml(a.title)}">${escapeHtml(a.title)}</span>
                          <span class="related-alert-meta">${_fmtDate(a.timestamp)}</span>
                      </div>
                      <div class="related-alert-actions">
                          ${hasCase
                              ? `<span class="case-badge" title="In case ${triage.case_number || triage.case_id}">${triage.case_number || 'Case'}</span>`
                              : currentCase
                                  ? `<button class="btn btn-xs btn-link" data-click-action="linkToCurrentCase" data-args='["${escapeHtml(a.id)}"]'>+ Link</button>`
                                  : ''
                          }
                      </div>
                  </div>
              `}).join('')}
              ${alerts.length > 10 ? `<div class="_ion-s-d5293cce9b">...and ${alerts.length - 10} more</div>` : ''}
          </div>
      `;
  }

  async function loadRelatedAlerts(alert) {
      const relatedContainer = document.getElementById('detail-tab-related');
      const timelineContainer = document.getElementById('detail-tab-timeline');

      try {
          const params = new URLSearchParams();
          if (alert.host) params.append('host', alert.host);
          if (alert.user) params.append('user', alert.user);
          if (alert.rule_name) params.append('rule_name', alert.rule_name);

          const response = await fetch(`/api/elasticsearch/alerts/${encodeURIComponent(alert.id)}/related?${params}`);
          if (!response.ok) throw new Error('Failed to load related alerts');

          const data = await response.json();
          const related = data.related || {};

          // Render related alerts tabs
          let relHtml = '';

          if (related.by_host && related.by_host.length > 0) {
              relHtml += renderRelatedSection('By Host', related.by_host, 'host');
          }
          if (related.by_user && related.by_user.length > 0) {
              relHtml += renderRelatedSection('By User', related.by_user, 'user');
          }
          if (related.by_rule && related.by_rule.length > 0) {
              relHtml += renderRelatedSection('By Rule', related.by_rule, 'rule');
          }

          if (!relHtml) {
              relHtml = '<div class="empty-state">No related alerts found</div>';
          }

          relatedContainer.innerHTML = relHtml;

          // Render timeline - merge all related alerts + current alert
          const allRelated = [
              ...(related.by_host || []),
              ...(related.by_user || []),
              ...(related.by_rule || [])
          ];

          // Deduplicate by id
          const seen = new Set();
          const timelineAlerts = [];
          // Add current alert
          timelineAlerts.push({ ...alert, _isCurrent: true });
          seen.add(alert.id);

          allRelated.forEach(a => {
              if (!seen.has(a.id)) {
                  seen.add(a.id);
                  timelineAlerts.push(a);
              }
          });

          // Sort chronologically
          timelineAlerts.sort((a, b) => new Date(a.timestamp) - new Date(b.timestamp));

          _timelineInto(timelineContainer, timelineAlerts);

      } catch (error) {
          console.error('Error loading related alerts:', error);
          relatedContainer.innerHTML = '<div class="empty-state">Failed to load related alerts</div>';
          timelineContainer.innerHTML = '<div class="empty-state">Failed to load timeline</div>';
      }
  }

  function renderAutoInvestigateReport(data) {
      const rep = data.report || {};
      const ev = data.evidence || [];
      const counts = data.counts || {};
      const verdict = String(rep.verdict || 'inconclusive');
      const vClass = _verdictClass(verdict);
      let h = '<div class="autoinv-report">';

      // Header: verdict + confidence + severity.
      h += '<div class="autoinv-head">'
         + '<span class="autoinv-verdict ' + vClass + '">' + escapeHtml(verdict.replace(/_/g, ' ')) + '</span>'
         + '<span class="autoinv-meta">confidence: <strong>' + escapeHtml(String(rep.confidence_level || '?')) + '</strong></span>'
         + '<span class="autoinv-meta">severity: <strong>' + escapeHtml(String(rep.severity || '?')) + '</strong></span>'
         + '<button type="button" class="btn btn-ghost btn-sm" data-click-action="runAutoInvestigate" title="Re-run">&#8635; Re-run</button>'
         + '</div>';

      // Transparency notice from server-side citation validation.
      const val = rep.validation || {};
      if (val.verdict_downgraded || val.dropped_citations || val.invalid_playbook) {
          const notes = [];
          if (val.verdict_downgraded) notes.push('verdict downgraded to inconclusive (no cited evidence supported a decisive verdict)');
          if (val.dropped_citations) notes.push(val.dropped_citations + ' invalid citation(s) dropped');
          if (val.dropped_findings) notes.push(val.dropped_findings + ' unsupported finding(s) dropped');
          if (val.invalid_playbook) notes.push('a recommended playbook id was not in the catalogue and was discarded');
          h += '<div class="autoinv-validation">&#9888; ' + escapeHtml(notes.join('; ')) + '</div>';
      }

      if (rep.summary) h += '<div class="autoinv-summary">' + escapeHtml(String(rep.summary)) + '</div>';
      if (rep.analyst_explanation) h += '<div class="autoinv-explain">' + escapeHtml(String(rep.analyst_explanation)) + '</div>';

      // Findings (each cites evidence).
      if ((rep.findings || []).length) {
          h += '<div class="autoinv-section-title">Findings</div><ul class="autoinv-findings">';
          for (const f of rep.findings) {
              h += '<li>' + escapeHtml(String(f.claim || '')) + _refBadges(f.evidence_refs) + '</li>';
          }
          h += '</ul>';
      }

      // Key observations.
      if ((rep.key_observations || []).length) {
          h += '<div class="autoinv-section-title">Key observations</div><table class="autoinv-obs"><tbody>';
          for (const o of rep.key_observations) {
              h += '<tr><td class="autoinv-obs-k">' + escapeHtml(String(o.field || '')) + '</td>'
                 + '<td>' + escapeHtml(String(o.value || '')) + ' <span class="autoinv-sig">' + escapeHtml(String(o.significance || '')) + '</span>'
                 + _refBadges(o.evidence_refs) + '</td></tr>';
          }
          h += '</tbody></table>';
      }

      // Recommended playbook.
      if (rep.recommended_playbook && rep.recommended_playbook.name) {
          const pb = rep.recommended_playbook;
          h += '<div class="autoinv-section-title">Recommended playbook</div>'
             + '<div class="autoinv-playbook"><strong>' + escapeHtml(String(pb.name)) + '</strong>'
             + (pb.rationale ? ' — ' + escapeHtml(String(pb.rationale)) : '') + '</div>';
      }

      // Recommended actions.
      if ((rep.recommended_actions || []).length) {
          h += '<div class="autoinv-section-title">Recommended actions</div><ul class="autoinv-actions">';
          for (const a of rep.recommended_actions) {
              const txt = (typeof a === 'string') ? a : (a.action || '');
              const pri = (typeof a === 'object' && a.priority) ? (escapeHtml(String(a.priority)) + ' · ') : '';
              h += '<li>' + pri + escapeHtml(String(txt)) + '</li>';
          }
          h += '</ul>';
      }

      // MITRE.
      const mi = rep.mitre || {};
      const tech = (mi.techniques || []).concat(mi.tactics || []);
      if (tech.length) {
          h += '<div class="autoinv-section-title">MITRE ATT&amp;CK</div><div class="autoinv-mitre">'
             + tech.map(t => '<span class="autoinv-tag">' + escapeHtml(String(t)) + '</span>').join(' ') + '</div>';
      }

      // Evidence ledger.
      h += '<div class="autoinv-section-title">Evidence ledger (' + ev.length + ')</div>';
      if (!ev.length) {
          h += '<div class="autoinv-empty">No corroborating evidence was found — Bob reasoned from the subject alone.</div>';
      } else {
          h += '<table class="autoinv-ledger"><tbody>';
          for (const it of ev) {
              let detail = '';
              const d = it.detail || {};
              const parts = [];
              for (const k of Object.keys(d)) {
                  if (d[k] === null || d[k] === '' || (Array.isArray(d[k]) && !d[k].length)) continue;
                  parts.push(escapeHtml(k) + ': ' + escapeHtml(String(Array.isArray(d[k]) ? d[k].join(', ') : d[k])));
              }
              detail = parts.join(' · ');
              h += '<tr><td class="autoinv-eid"><span class="autoinv-ref">' + escapeHtml(String(it.id)) + '</span></td>'
                 + '<td><span class="autoinv-ekind">' + escapeHtml(String(it.kind)) + '</span> ' + escapeHtml(String(it.title))
                 + (detail ? '<div class="autoinv-edetail">' + detail + '</div>' : '') + '</td></tr>';
          }
          h += '</tbody></table>';
      }

      // Sources footer.
      const srcBits = Object.keys(counts).map(k => counts[k] + ' ' + k.replace(/_/g, ' ')).join(' · ');
      if (srcBits) h += '<div class="autoinv-sources">Gathered: ' + escapeHtml(srcBits) + (data.model ? ' · model: ' + escapeHtml(String(data.model)) : '') + '</div>';

      h += '</div>';
      return h;
  }

  function runAutoInvestigate() {
      if (!_current) return;
      const c = document.getElementById('autoinv-content');
      if (!c) return;
      c.innerHTML = '<div class="loading">Bob is investigating — gathering evidence and reasoning (this can take 15-60s)…</div>';
      fetch('/api/elasticsearch/alerts/' + encodeURIComponent(_current.id) + '/auto-investigate', { method: 'POST' })
          .then(async r => {
              if (!r.ok) { const d = await r.json().catch(() => ({})); throw new Error(d.detail || ('HTTP ' + r.status)); }
              return r.json();
          })
          .then(data => { c.innerHTML = renderAutoInvestigateReport(data); })
          .catch(e => {
              c.innerHTML = '<div class="autoinv-error">Auto-Investigate failed: ' + escapeHtml(String((e && e.message) || e)) + '</div>'
                  + '<button type="button" class="btn btn-secondary" data-click-action="runAutoInvestigate">Retry</button>';
          });
  }

  async function aiAnalyzeAlert(alertId) {
      const container = document.getElementById('ai-analysis-result');
      if (!container) return;
      const payload = _alertPayload(alertId);
      if (!payload) return;

      container.className = 'ai-analysis-result visible';
      container.innerHTML = '<div class="ai-loading"><div class="ai-spinner"></div>Analyzing alert with AI...</div>';

      try {
          const resp = await fetch('/api/ai/analyze/alert', {
              method: 'POST',
              headers: { 'Content-Type': 'application/json' },
              body: JSON.stringify(payload),
          });
          if (!resp.ok) throw new Error('AI service unavailable');
          const data = await resp.json();
          container.innerHTML = `
              <div class="ai-result-header">
                  <span>AI Analysis</span>
                  <span class="ai-model-tag">${escapeHtml(data.model || '')}</span>
              </div>
              <div class="ai-result-body">${_aiContent(escapeHtml(data.analysis || ''))}</div>
          `;
      } catch (e) {
          container.innerHTML = `<div class="ai-error">AI analysis failed: ${escapeHtml(e.message)}</div>`;
      }
  }

  function openAIChatWithContext(alertId) {
      if (!_opts.aiAvailable) {
          _notify('AI service is not available', 'error');
          return;
      }

      const payload = _alertPayload(alertId);
      if (!payload) return;

      // Build context message
      let context = `I'm investigating this security alert and need your help:\n\n`;
      context += `Alert: ${payload.title}\n`;
      context += `Severity: ${payload.severity}\n`;
      context += `Rule: ${payload.rule_name || 'N/A'}\n`;
      context += `Host: ${payload.host || 'N/A'}\n`;
      context += `User: ${payload.user || 'N/A'}\n`;
      context += `Source IP: ${payload.source_ip || 'N/A'}\n`;
      context += `Destination IP: ${payload.destination_ip || 'N/A'}\n`;
      if (payload.mitre_technique_id) {
          context += `MITRE: ${payload.mitre_technique_id} - ${payload.mitre_technique_name || ''} (${payload.mitre_tactic_name || ''})\n`;
      }
      context += `Message: ${payload.message || 'N/A'}\n`;

      if (payload.triage_status) context += `\nTriage Status: ${payload.triage_status}`;
      if (payload.triage_priority) context += `\nPriority: ${payload.triage_priority}`;

      if (payload.observables && payload.observables.length > 0) {
          context += `\n\nObservables:\n`;
          payload.observables.forEach(obs => {
              context += `- ${obs.type}: ${obs.value}\n`;
          });
      }

      // Include enrichment results if available
      const enrichResults = document.getElementById('enrich-results');
      if (enrichResults && enrichResults.innerText.trim()) {
          context += `\nOpenCTI Enrichment Results:\n${enrichResults.innerText.trim()}\n`;
      }

      context += `\nHelp me investigate this alert. What are the key findings, potential impact, and recommended next steps?`;

      // Open chat panel if closed
      const panel = document.getElementById('chat-panel');
      if (!panel || !panel.classList.contains('open')) {
          if (typeof window.toggleChat === 'function') window.toggleChat();
      }

      // Open AI chat, set analyst context, and send
      setTimeout(() => {
          openAIChat();
          clearAIChat();
          aiContextType = 'analyst';
          const contextSelect = document.getElementById('ai-context-select');
          if (contextSelect) contextSelect.value = 'analyst';
          sendAIQuickPrompt(context);
      }, 200);
  }

  function switchDetailTab(tabId, btn) {
      document.querySelectorAll('.detail-tab-btn').forEach(b => b.classList.remove('active'));
      document.querySelectorAll('.detail-tab-content').forEach(c => c.classList.remove('active'));
      btn.classList.add('active');
      document.getElementById(`detail-tab-${tabId}`).classList.add('active');
      // Lazy-load sequence events (EQL building blocks) on first click
      if (tabId === 'sequence' && _current) {
          const seqEl = document.getElementById('sequence-content');
          if (seqEl && seqEl.classList.contains('loading')) {
              seqEl.innerHTML = '<div class="loading">Loading sequence events...</div>';
              fetch(`/api/elasticsearch/alerts/${encodeURIComponent(_current.id)}/sequence`)
                  .then(r => r.json())
                  .then(data => {
                      const events = data.events || [];
                      if (!events.length) {
                          seqEl.innerHTML = '<div class="empty-state _ion-s-c8739bb5cb">No sequence events — this is not an EQL/correlation alert, or building blocks are not available.</div>';
                          return;
                      }
                      let html = '<div class="_ion-s-1b291a2eeb">' + events.length + ' events in this sequence</div>';
                      html += '<div class="sequence-timeline">';
                      events.forEach((ev, i) => {
                          const ts = ev.timestamp ? new Date(ev.timestamp).toLocaleString() : '';
                          html += '<div class="_ion-s-11d17c6fcf">';
                          html += '<div class="_ion-s-1412b0aeb4"></div>';
                          html += '<div class="_ion-s-ba1f79c91c">Step ' + (i+1) + ' &middot; ' + escapeHtml(ts) + '</div>';
                          if (ev.process_name) html += '<div class="_ion-s-c188ad004a"><span class="_ion-s-081bc4f452">Process:</span> <span class="_ion-s-df570f8a04">' + escapeHtml(ev.process_name) + '</span></div>';
                          if (ev.command_line) html += '<div class="_ion-s-c188ad004a"><span class="_ion-s-081bc4f452">Command:</span> <span class="_ion-s-ac046f947e">' + escapeHtml(ev.command_line) + '</span></div>';
                          if (ev.parent_process) html += '<div class="_ion-s-c188ad004a"><span class="_ion-s-081bc4f452">Parent:</span> <span class="_ion-s-de3b9d4658">' + escapeHtml(ev.parent_process) + '</span></div>';
                          if (ev.file_name) html += '<div class="_ion-s-c188ad004a"><span class="_ion-s-081bc4f452">File:</span> <span class="_ion-s-df570f8a04">' + escapeHtml(ev.file_name) + '</span></div>';
                          if (ev.file_hash) html += '<div class="_ion-s-c188ad004a"><span class="_ion-s-081bc4f452">Hash:</span> <span class="_ion-s-83a55422b8">' + escapeHtml(ev.file_hash) + '</span></div>';
                          if (ev.source_ip || ev.destination_ip) html += '<div class="_ion-s-c188ad004a"><span class="_ion-s-081bc4f452">Network:</span> <span class="_ion-s-df570f8a04">' + escapeHtml(ev.source_ip || '') + ' &rarr; ' + escapeHtml(ev.destination_ip || '') + '</span></div>';
                          if (ev.host) html += '<div class="_ion-s-c188ad004a"><span class="_ion-s-081bc4f452">Host:</span> <span class="_ion-s-8d655b9a89">' + escapeHtml(ev.host) + '</span></div>';
                          if (ev.user) html += '<div class="_ion-s-c188ad004a"><span class="_ion-s-081bc4f452">User:</span> <span class="_ion-s-8d655b9a89">' + escapeHtml(ev.user) + '</span></div>';
                          if (ev.event_action) html += '<div><span class="_ion-s-081bc4f452">Action:</span> <span class="_ion-s-8d3d885daf">' + escapeHtml(ev.event_action) + '</span></div>';
                          html += '</div>';
                      });
                      html += '</div>';
                      seqEl.innerHTML = html;
                      seqEl.classList.remove('loading');
                  })
                  .catch(() => { seqEl.innerHTML = '<div class="error">Failed to load sequence</div>'; });
          }
      }
      // Render from cache when we already have the document, otherwise fetch.
      // Guarding on `!raw_data` would strand the tab on its placeholder once
      // hydration or the Fields tab had populated it.
      if (tabId === 'rawdata' && _current) {
          const container = document.getElementById('raw-data-content');
          if (container && container.querySelector('.loading') && _current.raw_data) {
              container.innerHTML = syntaxHighlightJSON(_current.raw_data);
          } else if (container && container.querySelector('.loading')) {
              container.innerHTML = '<div class="loading">Loading raw data...</div>';
              // through the coalescer like every other consumer. On
              // /alerts this is the tab-click path, so it also benefits: opening
              // Raw Data after Fields now reuses the document already fetched.
              fetchRawOnce(_current.id)
                  .then(raw => {
                      if (!raw) { container.innerHTML = '<div class="error">No raw data available</div>'; return; }
                      _current.raw_data = raw;
                      container.innerHTML = syntaxHighlightJSON(raw);
                  })
                  .catch(() => { container.innerHTML = '<div class="error">Failed to load raw data</div>'; });
          }
      }
      // Lazy-load the parsed-fields view on first click (same logic as the
      // /cases linked-alert dropdown: extracted values + well-known fields + show-all).
      if (tabId === 'fields' && _current) {
          const container = document.getElementById('alert-fields-content');
          if (container && container.querySelector('.loading')) {
              loadAlertParsedFields(_current.id, container);
          }
      }
      // Related and Timeline share one /related response.
      if ((tabId === 'related' || tabId === 'timeline') && _current && !_relatedLoaded) {
          _relatedLoaded = true;
          loadRelatedAlerts(_current);
      }
      // Fetched on first click; previously only /alerts filled this.
      if (tabId === 'comments' && _current && !_commentsLoaded) {
          _commentsLoaded = true;
          loadAlertComments(_current.id);
      }
  }

  /* KEV status and System-Quirk annotations.
   *
   * Both have been attached to the alerts API for releases with nothing
   * rendering them: quirks since v0.57.0, KEV as Bob prompt ground truth since
   * v0.79.1. Bob was told which CVEs are actively exploited; the analyst
   * reading the same alert was not.
   *
   * Placed above the metadata grid because both change what you do first. A
   * KEV miss is NOT rendered — a snapshot cannot know about a CVE published
   * after it was cut, and "not in KEV" reads as safety.
   */
  function _advisoriesHtml(alert) {
    var kev = Array.isArray(alert.kev) ? alert.kev : [];
    var quirks = Array.isArray(alert.quirks) ? alert.quirks : [];
    if (!kev.length && !quirks.length) return '';

    var h = '<div class="iad-advisories">';

    if (kev.length) {
      var ransom = kev.some(function (k) { return k.known_ransomware; });
      h += '<div class="iad-adv iad-adv-kev' + (ransom ? ' is-ransomware' : '') + '">'
         + '<div class="iad-adv-t">Known exploited vulnerability'
         + (ransom ? ' — linked to ransomware campaigns' : '') + '</div>';
      kev.forEach(function (k) {
        h += '<div class="iad-adv-row"><b>' + escapeHtml(k.cve_id) + '</b>'
           + (k.vulnerability_name ? ' — ' + escapeHtml(k.vulnerability_name) : '')
           + (k.date_added ? '<span class="iad-adv-m">added ' + escapeHtml(k.date_added) + '</span>' : '')
           + (k.due_date ? '<span class="iad-adv-m">remediate by ' + escapeHtml(k.due_date) + '</span>' : '')
           + '</div>';
      });
      h += '<div class="iad-adv-note">On CISA\'s catalogue of vulnerabilities with '
         + 'evidence of active exploitation. This is triage context, not an automatic '
         + 'severity or verdict.</div></div>';
    }

    if (quirks.length) {
      h += '<div class="iad-adv iad-adv-quirk"><div class="iad-adv-t">System quirk</div>';
      quirks.forEach(function (q) {
        h += '<div class="iad-adv-row"><b>' + escapeHtml(q.title || '') + '</b>'
           + (q.annotation ? '<div class="iad-adv-a">' + escapeHtml(q.annotation) + '</div>' : '')
           + '</div>';
      });
      h += '<div class="iad-adv-note"><b>Advisory only.</b> The alert is shown in full '
         + 'and is not down-ranked; a quirk never suppresses anything.</div></div>';
    }

    return h + '</div>';
  }

  function _renderHead(alert) {
    // Only rendered when the host can fill it; renderTriageBar lives in
    // alerts.html and nowhere else.
    let html = _opts.triageBar === false
        ? ''
        : `<div class="triage-bar" id="triage-bar"><span class="_ion-s-75f6ba34af">Loading triage...</span></div>`;

    html += _advisoriesHtml(alert);

    // Metadata grid
    html += `<div class="alert-meta-grid">
        <div class="alert-meta-item">
            <div class="alert-meta-label">Severity</div>
            <div class="alert-meta-value"><span class="severity-badge severity-${alert.severity}">${alert.severity}</span></div>
        </div>
        <div class="alert-meta-item">
            <div class="alert-meta-label">Status</div>
            <div class="alert-meta-value"><span class="status-badge alert-status-${alert.status}">${alert.status}</span></div>
        </div>
        <div class="alert-meta-item">
            <div class="alert-meta-label">Host</div>
            <div class="alert-meta-value" id="iad-meta-host">${escapeHtml(alert.host || '-')}</div>
        </div>
        <div class="alert-meta-item">
            <div class="alert-meta-label">User</div>
            <div class="alert-meta-value" id="iad-meta-user">${escapeHtml(alert.user || '-')}</div>
        </div>
        <div class="alert-meta-item">
            <div class="alert-meta-label">Source</div>
            <div class="alert-meta-value" id="iad-meta-source">${escapeHtml(alert.source || '-')}</div>
        </div>
        <div class="alert-meta-item">
            <div class="alert-meta-label">Rule</div>
            <div class="alert-meta-value">${escapeHtml(alert.rule_name || '-')}</div>
        </div>
        <div class="alert-meta-item">
            <div class="alert-meta-label">System</div>
            <div class="alert-meta-value">${renderSystemBadge(alert)}</div>
        </div>
        <div class="alert-meta-item">
            <div class="alert-meta-label">Timestamp</div>
            <div class="alert-meta-value" id="iad-meta-timestamp">${
                alert.timestamp ? new Date(alert.timestamp).toLocaleString() : '-'
            }</div>
        </div>
    </div>`;

    // Message — wrap so the v0.17.0 Translate button can replace its body in place.
    html += `<div class="alert-message-box" id="alert-message-box" data-original-message="${escapeHtml(alert.message || '')}">${escapeHtml(alert.message)}</div>`;
    html += `<div class="alert-msg-translate-row _ion-s-379195f8b9">
        <button class="btn btn-ghost btn-sm _ion-s-938b812d49" type="button" data-click-action="translateAlertMessage">
            Translate
        </button>
        <select class="_ion-s-d81e1fcfa4" id="alert-msg-translate-target">
            <option value="en" selected>→ English</option>
            <option value="ru">→ Russian</option>
            <option value="zh">→ Chinese</option>
            <option value="ar">→ Arabic</option>
            <option value="es">→ Spanish</option>
            <option value="fr">→ French</option>
            <option value="de">→ German</option>
        </select>
        <span class="_ion-s-93e6231cbb" id="alert-msg-translate-status"></span>
        <button class="_ion-s-df01b7ca34" id="alert-msg-translate-revert" type="button" data-click-action="revertAlertMessage">show original</button>
    </div>`;

    // Tags
    if (alert.tags && alert.tags.length > 0) {
        html += `<div class="alert-tags">${alert.tags.map(t => `<span class="alert-tag">${escapeHtml(t)}</span>`).join('')}</div>`;
    }

    // MITRE ATT&CK Badges (auto-detected from alert)
    if (alert.mitre_technique_id) {
        html += `<div class="mitre-badges-row">
            <span class="mitre-badge auto" data-click-action="__filterMitreAndClose" data-tech-id="${escapeHtml(alert.mitre_technique_id)}" title="Click to filter by this technique">
                <strong>${escapeHtml(alert.mitre_technique_id)}</strong>
                ${alert.mitre_technique_name ? ` - ${escapeHtml(alert.mitre_technique_name)}` : ''}
                ${alert.mitre_tactic_name ? ` <span class="_ion-s-68433eba3d">(${escapeHtml(alert.mitre_tactic_name)})</span>` : ''}
            </span>
        </div>`;
    }

    // AI Analysis Bar
    if (_opts.aiAvailable) {
        html += `<div class="ai-analysis-bar">
            <button class="ai-assist-btn" data-click-action="aiAnalyzeAlert" data-args='["${escapeHtml(alert.id)}"]'>&#9733; AI Analyze</button>
            <button class="ai-assist-btn _ion-s-f34a398ced" data-click-action="openAIChatWithContext" data-args='["${escapeHtml(alert.id)}"]'>&#9993; Discuss with AI</button>
            <div class="ai-analysis-result" id="ai-analysis-result"></div>
        </div>`;
    }

    // Arkime PCAP button — shown when Arkime is configured and alert has network context
    if (_opts.arkimeEnabled && (alert.network_community_id || alert.source_ip || alert.destination_ip || alert.arkime_node)) {
        const arkimeHint = alert.network_community_id
            ? `Community ID: ${escapeHtml(alert.network_community_id)}`
            : `IP search: ${escapeHtml(alert.source_ip || alert.destination_ip || '')}`;
        html += `<div class="ai-analysis-bar _ion-s-04cdf78d3c">
            <a class="ai-assist-btn _ion-s-5acbd5004f" href="/alerts/${encodeURIComponent(alert.id)}/arkime"
>
                <svg class="_ion-s-a574d58441" width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><rect x="16" y="16" width="6" height="6" rx="1"/><rect x="2" y="16" width="6" height="6" rx="1"/><rect x="9" y="2" width="6" height="6" rx="1"/><path d="M5 16v-3a1 1 0 0 1 1-1h12a1 1 0 0 1 1 1v3"/><path d="M12 12V8"/></svg>
                Arkime PCAP Analysis
            </a>
            <span class="_ion-s-e23b35fe83">${arkimeHint}</span>
        </div>`;
    }
    return html;
  }

  // -- section shell: the ONLY thing that differs between the two layouts ----
  // A host declares which sections it can populate; default is all. Rendering a
  // section the host cannot fill leaves a spinner that never resolves.
  function _visibleSections() {
    var allow = _opts.sections;
    if (!allow || !allow.length) return SECTIONS;
    return SECTIONS.filter(function (s) { return allow.indexOf(s.id) !== -1; });
  }

  function _sectionsHtml(alert) {
    var stacked = _opts.layout === 'stacked';
    var SECTIONS = _visibleSections();
    var h = '';

    if (stacked) {
      // Jump-links, not tabs - they scroll, they do not hide. This is what
      // takes /cases from eight clicks per alert down to zero.
      h += '<div class="iad-jump" role="navigation" aria-label="Alert sections">';
      SECTIONS.forEach(function (s, i) {
        h += '<a class="iad-jump-link' + (i === 0 ? ' active' : '') + '" href="#iad-sec-' + s.id + '"'
           + ' data-click-action="ionAlertDetailJump" data-section="' + s.id + '">' + s.label + '</a>';
      });
      h += '</div>';
      SECTIONS.forEach(function (s) {
        h += '<section class="iad-section" id="iad-sec-' + s.id + '">'
           + '<h4 class="iad-section-title">' + s.label + '</h4>'
           + '<div id="detail-tab-' + s.id + '" class="detail-tab-content active">'
           + _sectionPlaceholder(s.id, alert)
           + '</div></section>';
      });
      return h;
    }

    h += '<div class="detail-tabs">';
    SECTIONS.forEach(function (s, i) {
      h += '<button class="detail-tab-btn' + (i === 0 ? ' active' : '') + '" data-tab="' + s.id + '"'
         + ' data-click-action="switchDetailTab" data-args=\'["' + s.id + '", "$target"]\'>' + s.label + '</button>';
    });
    h += '</div>';
    SECTIONS.forEach(function (s, i) {
      h += '<div id="detail-tab-' + s.id + '" class="detail-tab-content' + (i === 0 ? ' active' : '') + '">'
         + _sectionPlaceholder(s.id, alert) + '</div>';
    });
    return h;
  }

  function _sectionPlaceholder(id, alert) {
    switch (id) {
      case 'related':  return '<div class="loading">Loading related alerts...</div>';
      case 'timeline': return '<div class="loading">Loading timeline...</div>';
      case 'comments': return '<div class="loading">Loading comments...</div>';
      case 'case':     return '<div class="loading">Loading case info...</div>';
      case 'sequence': return '<div id="sequence-content" class="loading">Click to load sequence events...</div>';
      case 'autoinvestigate':
        return '<div id="autoinv-content">'
          + '<p class="autoinv-intro">Bob gathers related alerts, observable &amp; threat-intel enrichment, '
          + 'the sequence, and similar closed cases, then produces a cited verdict + recommended playbook. '
          + 'Every finding cites the evidence it rests on.</p>'
          + '<button type="button" class="btn btn-primary" data-click-action="runAutoInvestigate">'
          + '\uD83D\uDD0D Run Auto-Investigate</button></div>';
      case 'fields':   return '<div id="alert-fields-content"><div class="loading">Click to load parsed fields...</div></div>';
      case 'rawdata':  return '<div class="raw-data-container" id="raw-data-content">'
          + (alert.raw_data ? syntaxHighlightJSON(alert.raw_data)
                            : '<div class="loading">Click to load raw data...</div>') + '</div>';
      default: return '';
    }
  }

  // -- public API -----------------------------------------------------------
  function render(alert, opts) {
    _opts = opts || {};
    _current = alert;
    return _renderHead(alert) + _sectionsHtml(alert);
  }

  // ── hydrate thin alerts from the raw document ─────────────────
  //
  // /alerts hands this component a full Elasticsearch document. /cases hands it
  // a row from /api/cases/{id}, which carries only es_alert_id, rule_name,
  // status, priority, observables, mitre_techniques and analyst_notes — a
  // projection built for the old narrow slide-out, which showed a rule name and
  // little else. v0.77.0 pointed a full-detail component at it, so Host, User,
  // Source, Timestamp and the message rendered blank on a case.
  //
  // Rather than widening the case API (ION's own tables do not hold host/user
  // either — they live in Elasticsearch), fill the gaps from the /raw document
  // this component already fetches. Costs no extra request: fetchRawOnce is
  // shared with the Fields and Raw Data sections.
  function _ecs(src, dotted) {
    if (!src) return undefined;
    if (src[dotted] !== undefined) return src[dotted];   // flattened form
    return dotted.split('.').reduce(function (o, k) {
      return (o && typeof o === 'object') ? o[k] : undefined;
    }, src);
  }

  function _firstOf(src, paths) {
    for (var i = 0; i < paths.length; i++) {
      var v = _ecs(src, paths[i]);
      if (Array.isArray(v)) v = v[0];
      if (v !== undefined && v !== null && String(v).trim() !== '') return String(v);
    }
    return undefined;
  }

  function _setMeta(id, value) {
    var el = document.getElementById(id);
    // Only fill a genuine blank — never overwrite something the caller supplied.
    if (el && value && (el.textContent === '-' || el.textContent.trim() === '')) {
      el.textContent = value;
    }
  }

  function _hydrateFromRaw(alert) {
    if (!alert || !alert.id) return;
    var needs = !alert.host || !alert.user || !alert.timestamp || !alert.source;
    if (!needs) return;
    fetchRawOnce(alert.id).then(function (raw) {
      if (!raw) return;
      var host = _firstOf(raw, ['host.name', 'host.hostname', 'agent.name', 'winlog.computer_name']);
      var user = _firstOf(raw, ['user.name', 'winlog.event_data.SubjectUserName',
                                'winlog.event_data.TargetUserName', 'source.user.name']);
      var ts   = _firstOf(raw, ['@timestamp', 'event.created', 'timestamp']);
      var src  = _firstOf(raw, ['event.dataset', 'data_stream.dataset', 'event.module']);
      var msg  = _firstOf(raw, ['message', 'kibana.alert.reason', 'signal.rule.description']);

      if (host && !alert.host) alert.host = host;
      if (user && !alert.user) alert.user = user;
      if (ts && !alert.timestamp) alert.timestamp = ts;
      if (src && !alert.source) alert.source = src;

      _setMeta('iad-meta-host', host);
      _setMeta('iad-meta-user', user);
      _setMeta('iad-meta-source', src);
      if (ts) _setMeta('iad-meta-timestamp', new Date(ts).toLocaleString());

      var box = document.getElementById('alert-message-box');
      if (box && msg && !box.textContent.trim()) {
        box.textContent = msg;
        box.setAttribute('data-original-message', msg);
      }
    }).catch(function () { /* the grid keeps its dashes */ });
  }

  // ── fill from the observables ION already extracted ───────────
  //
  // ION extracts hostname/user from the alert at triage time
  // (services/observable_extractor.py) and stores them on AlertTriage
  // .observables — and /api/cases/{id} already RETURNS that array per alert.
  // So the case page holds this data before it renders anything, and going
  // back to Elasticsearch for it would be re-deriving what we were handed.
  //
  // Runs BEFORE render, synchronously, so the grid is correct on first paint
  // with no flicker and no dependency on Elasticsearch being reachable — which
  // matters, because a case is exactly what an analyst opens when the estate is
  // having a bad day.
  var _OBS_HOST = ['hostname', 'host', 'source_hostname'];
  var _OBS_USER = ['user_account', 'target_user', 'source_user', 'username'];

  function _fromObservables(alert) {
    if (!alert || !Array.isArray(alert.observables)) return;
    var byType = {};
    alert.observables.forEach(function (o) {
      if (o && o.type && o.value && byType[o.type] === undefined) byType[o.type] = o.value;
    });
    function pick(types) {
      for (var i = 0; i < types.length; i++) {
        if (byType[types[i]]) return byType[types[i]];
      }
      return undefined;
    }
    if (!alert.host) alert.host = pick(_OBS_HOST);
    if (!alert.user) alert.user = pick(_OBS_USER);
  }

  function mount(container, alert, opts) {
    if (!container) return;
    _relatedLoaded = false;           // new alert — the shared fetch must re-run
    _commentsLoaded = false;
    _fromObservables(alert);          // free — the data is already in hand
    container.innerHTML = render(alert, opts);
    _hydrateFromRaw(alert);           // only for what observables cannot supply
    // In stacked layout every section is already on screen, so nothing is
    // lazy - load the ones that would otherwise wait for a click the analyst
    // is never going to make.
    if (_opts.layout === 'stacked') {
      _relatedLoaded = true;
      loadRelatedAlerts(alert);
      var f = document.getElementById('alert-fields-content');
      if (f) loadAlertParsedFields(alert.id, f);
      _loadRawInto(document.getElementById('raw-data-content'), alert);
      _observeSections();
      return;
    }
    // Load only the section on screen; the rest fetch when first opened.
    var first = _visibleSections()[0];
    if (first) _loadSection(first.id, alert);
  }

  // Mirrors switchDetailTab's lazy branches for the initially-visible tab.
  function _loadSection(id, alert) {
    if (id === 'related' || id === 'timeline') {
      _relatedLoaded = true;
      loadRelatedAlerts(alert);
      return;
    }
    if (id === 'fields') {
      var f = document.getElementById('alert-fields-content');
      if (f) loadAlertParsedFields(alert.id, f);
      return;
    }
    if (id === 'comments') {
      _commentsLoaded = true;
      loadAlertComments(alert.id);
      return;
    }
    if (id === 'rawdata') {
      _loadRawInto(document.getElementById('raw-data-content'), alert);
    }
  }

  function _loadRawInto(el, alert) {
    if (!el) return;
    if (alert.raw_data) { el.innerHTML = syntaxHighlightJSON(alert.raw_data); return; }
    // Shares the in-flight request with the Fields section and (on /cases) the
    // rule guide instead of issuing a third identical one.
    fetchRawOnce(alert.id)
      .then(function (raw) {
        if (!raw) { el.innerHTML = '<div class="error">No raw data available</div>'; return; }
        alert.raw_data = raw;
        el.innerHTML = syntaxHighlightJSON(raw);
      })
      .catch(function () { el.innerHTML = '<div class="error">Failed to load raw data</div>'; });
  }

  // Highlight whichever jump-link corresponds to the section on screen.
  function _observeSections() {
    if (!window.IntersectionObserver) return;
    var links = document.querySelectorAll('.iad-jump-link');
    if (!links.length) return;
    var io = new IntersectionObserver(function (entries) {
      entries.forEach(function (e) {
        if (!e.isIntersecting) return;
        var id = e.target.id.replace('iad-sec-', '');
        links.forEach(function (a) {
          a.classList.toggle('active', a.getAttribute('data-section') === id);
        });
      });
    }, { rootMargin: '-20% 0px -70% 0px' });
    document.querySelectorAll('.iad-section').forEach(function (s) { io.observe(s); });
  }

  function showSection(name) {
    if (!name) return;
    var el = document.getElementById('iad-sec-' + name);
    if (el) { el.scrollIntoView({ behavior: 'smooth', block: 'start' }); return; }
    var btn = document.querySelector('.detail-tab-btn[data-tab="' + name + '"]');
    if (btn) btn.click();
  }

  window.ionAlertDetail = {
    render: render,
    mount: mount,
    showSection: showSection,
    SECTIONS: SECTIONS,
    get current() { return _current; },
    set current(a) { _current = a; }
  };

  // Delegated actions the rendered markup refers to. These were page-level
  // globals in alerts.html; exposing them here keeps every existing call site
  // working while making them available to /cases for the first time.
  window.ionAlertDetailJump = function (event, dataset) { showSection(dataset && dataset.section); };
  window.switchDetailTab = switchDetailTab;
  window.ionAlertAddComment = ionAlertAddComment;
  window.loadAlertComments = loadAlertComments;
  window.toggleAllAlertFields = toggleAllAlertFields;
  window.addAlertFieldsAsEvidence = addAlertFieldsAsEvidence;
  window.runAutoInvestigate = runAutoInvestigate;
  window.aiAnalyzeAlert = aiAnalyzeAlert;
  window.openAIChatWithContext = openAIChatWithContext;
  window.renderSystemBadge = renderSystemBadge;
  window.syntaxHighlightJSON = syntaxHighlightJSON;
  window.loadRelatedAlerts = loadRelatedAlerts;
  window.loadAlertParsedFields = loadAlertParsedFields;
  window.flattenAlertFields = flattenAlertFields;
  window.renderAlertParsedFields = renderAlertParsedFields;
})();
