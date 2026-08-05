/**
 * ION - shared alert-detail component  (v0.77.0)
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
      const extracted = _alertExtractedValuesBlock(alertId);
      const flat = flattenAlertFields(raw);
      const allKeys = Object.keys(flat).sort();
      if (!allKeys.length) {
          return extracted || '<div class="alert-parsed-empty">No fields available for this alert.</div>';
      }
      const isKey = k => ALERT_KEY_PREFIXES.some(p => k === p || k.startsWith(p));
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
      const caseId = (triageCache[alertId] || {}).case_id;
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
      const obs = alertId ? _alertExtractedObs(alertId) : [];
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

  async function loadAlertParsedFields(alertId, container) {
      if (_current && _current.raw_data) {
          container.innerHTML = renderAlertParsedFields(alertId, _current.raw_data);
          return;
      }
      container.innerHTML = '<div class="loading">Loading fields...</div>';
      try {
          const r = await fetch(`/api/elasticsearch/alerts/${encodeURIComponent(alertId)}/raw`);
          const data = await r.json().catch(() => ({}));
          if (!r.ok || !data.raw_data) {
              // Still surface extracted values even when the raw _source is gone.
              container.innerHTML = _alertExtractedValuesBlock(alertId)
                  || '<div class="alert-parsed-empty">No raw data available for this alert.</div>';
              return;
          }
          if (_current && _current.id === alertId) {
              _current.raw_data = data.raw_data;
          }
          container.innerHTML = renderAlertParsedFields(alertId, data.raw_data);
      } catch (e) {
          container.innerHTML = _alertExtractedValuesBlock(alertId)
              + '<div class="alert-parsed-empty">Failed to load fields: '
              + escapeHtml(String((e && e.message) || e)) + '</div>';
      }
  }

  function renderRelatedSection(title, alerts, matchType) {
      const currentCase = _current && triageCache[_current.id]?.case_id;

      return `
          <div class="related-section">
              <div class="related-section-header">
                  <h4>${title} (${alerts.length})</h4>
                  ${currentCase ? `<button class="btn btn-sm btn-secondary" data-click-action="linkAllToCase" data-args='["${matchType}", ${currentCase}]'>Link all to case</button>` : ''}
              </div>
              ${alerts.slice(0, 10).map(a => {
                  const triage = triageCache[a.id];
                  const inSameCase = triage && currentCase && triage.case_id === currentCase;
                  const hasCase = triage && triage.case_id;
                  const similarity = calculateSimilarity(_current, a, matchType);

                  return `
                  <div class="related-alert-item ${inSameCase ? 'same-case' : ''}">
                      <div class="related-alert-main" data-click-action="showAlertDetail" data-args='["${escapeHtml(a.id)}"]'>
                          <span class="severity-badge severity-${a.severity}">${a.severity}</span>
                          <span class="similarity-badge similarity-${similarity.level}" title="${similarity.reasons.join(', ')}">${similarity.score}%</span>
                          <span class="related-alert-title" title="${escapeHtml(a.title)}">${escapeHtml(a.title)}</span>
                          <span class="related-alert-meta">${formatDate(a.timestamp)}</span>
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

          renderTimeline(timelineContainer, timelineAlerts);

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
      const vClass = _AUTOINV_VERDICT_CLASS[verdict] || 'autoinv-v-inc';
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
              h += '<li>' + escapeHtml(String(f.claim || '')) + _autoinvRefBadges(f.evidence_refs) + '</li>';
          }
          h += '</ul>';
      }

      // Key observations.
      if ((rep.key_observations || []).length) {
          h += '<div class="autoinv-section-title">Key observations</div><table class="autoinv-obs"><tbody>';
          for (const o of rep.key_observations) {
              h += '<tr><td class="autoinv-obs-k">' + escapeHtml(String(o.field || '')) + '</td>'
                 + '<td>' + escapeHtml(String(o.value || '')) + ' <span class="autoinv-sig">' + escapeHtml(String(o.significance || '')) + '</span>'
                 + _autoinvRefBadges(o.evidence_refs) + '</td></tr>';
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
      const payload = getAlertPayload(alertId);
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
              <div class="ai-result-body">${formatAIContent(escapeHtml(data.analysis || ''))}</div>
          `;
      } catch (e) {
          container.innerHTML = `<div class="ai-error">AI analysis failed: ${escapeHtml(e.message)}</div>`;
      }
  }

  function openAIChatWithContext(alertId) {
      if (!_opts.aiAvailable) {
          showNotification('AI service is not available', 'error');
          return;
      }

      const payload = getAlertPayload(alertId);
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
          toggleChat();
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
      // Lazy-load raw data on first click
      if (tabId === 'rawdata' && _current && !_current.raw_data) {
          const container = document.getElementById('raw-data-content');
          if (container && container.querySelector('.loading')) {
              container.innerHTML = '<div class="loading">Loading raw data...</div>';
              fetch(`/api/elasticsearch/alerts/${encodeURIComponent(_current.id)}/raw`)
                  .then(r => r.json())
                  .then(data => {
                      _current.raw_data = data.raw_data;
                      container.innerHTML = syntaxHighlightJSON(data.raw_data);
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
  }

  function _renderHead(alert) {
    // Triage bar placeholder
    let html = `<div class="triage-bar" id="triage-bar"><span class="_ion-s-75f6ba34af">Loading triage...</span></div>`;

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
            <div class="alert-meta-value">${escapeHtml(alert.host || '-')}</div>
        </div>
        <div class="alert-meta-item">
            <div class="alert-meta-label">User</div>
            <div class="alert-meta-value">${escapeHtml(alert.user || '-')}</div>
        </div>
        <div class="alert-meta-item">
            <div class="alert-meta-label">Source</div>
            <div class="alert-meta-value">${escapeHtml(alert.source)}</div>
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
            <div class="alert-meta-value">${new Date(alert.timestamp).toLocaleString()}</div>
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
  function _sectionsHtml(alert) {
    var stacked = _opts.layout === 'stacked';
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

  function mount(container, alert, opts) {
    if (!container) return;
    container.innerHTML = render(alert, opts);
    // In stacked layout every section is already on screen, so nothing is
    // lazy - load the ones that would otherwise wait for a click the analyst
    // is never going to make.
    if (_opts.layout === 'stacked') {
      loadRelatedAlerts(alert);
      var f = document.getElementById('alert-fields-content');
      if (f) loadAlertParsedFields(alert.id, f);
      _loadRawInto(document.getElementById('raw-data-content'), alert);
      _observeSections();
    }
  }

  function _loadRawInto(el, alert) {
    if (!el || alert.raw_data) return;
    fetch('/api/elasticsearch/alerts/' + encodeURIComponent(alert.id) + '/raw')
      .then(function (r) { return r.json(); })
      .then(function (d) { alert.raw_data = d.raw_data; el.innerHTML = syntaxHighlightJSON(d.raw_data); })
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
