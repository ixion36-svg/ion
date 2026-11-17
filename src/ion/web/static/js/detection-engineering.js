/* Detection Engineering: eight tabs, their sub-views, and the header's
   destination, system and sync controls. Panels are server-rendered
   fragments; this file only decides which one to load and where. */

function cloneTemplate(id) {
    const template = document.getElementById(id);
    return template && template.content.firstElementChild ? template.content.firstElementChild.cloneNode(true) : null;
}

function deMessage(target, message, loading = false) {
    const element = typeof target === 'string' ? document.getElementById(target) : target;
    if (!element) return;
    const node = cloneTemplate(element.tagName === 'SELECT' ? 'de-option-template' : loading ? 'de-loading-template' : 'de-message-template');
    if (loading && element.tagName !== 'SELECT') node.querySelector('[data-loading-message]').textContent = message;
    else node.textContent = message;
    element.replaceChildren(node);
}

const deFragmentRequests = new WeakMap();
async function deLoadFragment(url, targetId, loadingMessage = 'Loading...', options = {}) {
    const target = typeof targetId === 'string' ? document.getElementById(targetId) : targetId;
    if (!target) return false;
    const request = {};
    deFragmentRequests.set(target, request);
    target.setAttribute('hx-sync', 'this:replace');
    if (!options.quiet) deMessage(target, loadingMessage, true);
    let success = false;
    let status = 0;
    const outcome = event => {
        if (event.detail.target !== target) return;
        status = event.detail.xhr.status;
        success = status >= 200 && status < 300;
    };
    document.addEventListener('htmx:afterRequest', outcome);
    const showFailure = () => {
        if (deFragmentRequests.get(target) !== request) return;
        if (target.tagName === 'SELECT') deMessage(target, options.failure || 'Unavailable');
        else if (target.querySelector('[data-loading-message]') || options.quiet) deMessage(target, status === 403
            ? 'Your role does not include the permission this panel needs.'
            : options.failure || 'Unable to load this panel. Refresh to try again.');
    };
    try {
        await htmx.ajax(options.method || 'GET', url, {target, source:target, swap:'innerHTML', values:options.values});
        if (!success) showFailure();
        return success;
    } catch (error) {
        showFailure();
        return false;
    } finally {
        document.removeEventListener('htmx:afterRequest', outcome);
    }
}

function deSetBadge(message, healthy = false) {
    const node = cloneTemplate('de-badge-template');
    node.querySelector('.de-tide-dot').classList.toggle('ok', healthy);
    node.querySelector('[data-sync-label]').textContent = message;
    document.getElementById('de-tide-badge').replaceChildren(...node.childNodes);
}

(function(){
'use strict';
if (document.body.dataset.page !== 'detection-engineering') return;

const API = '/api/cyab';
/* Each sub-view belongs to one tab. */
const SUB_TAB = {
    overview:'overview', attack:'coverage', d3fend:'coverage', systems:'systems',
    rules:'rules', health:'rules', killchains:'usecases', progression:'usecases',
    readiness:'readiness', emulation:'readiness', vulns:'readiness',
    requests:'work', proposals:'work', quirks:'work',
    scorecard:'bob', disagreements:'bob', abuse:'bob',
};
/* Older ids: this page's former tabs, and the anchors the absorbed pages'
   URLs redirect to (/detection-health -> #health, /log-sources -> #systems). */
const ALIASES = {
    posture:'overview', gaps:'attack', coverage:'attack', usecases:'killchains', execution:'health',
    metrics:'health', campaigns:'health', 'detection-health':'health', 'de-metrics':'health',
    'log-sources':'systems', logsources:'systems', 'platform-health':'systems',
    workbench:'requests', de:'requests', 'tuning-requests':'requests', 'de-proposals':'proposals',
    'de-quirks':'quirks', bob:'scorecard', 'de-bob':'scorecard', oversight:'abuse', 'de-oversight':'abuse',
    actor:'readiness', work:'requests',
};
let _tabSub = {overview:'overview', coverage:'attack', systems:'systems', rules:'rules', usecases:'killchains',
               readiness:'readiness', work:'requests', bob:'scorecard'};
let _activeSub = 'overview';
let _loaded = {};
let _selectedSystemId = '';
let _openSystemId = '';
let _rulesQuery = {q:'', kind:'', severity:'', state:'', problems:'', offset:0};
let _progHours = 24;
let _readinessSearch = '';

function $(id){ return document.getElementById(id); }
async function apiFetch(path) {
    const r = await fetch(API + path, {credentials:'include'});
    if (!r.ok) throw new Error(`${r.status}`);
    return r.json();
}
function resolve(id) {
    const sub = ALIASES[id] || id;
    return SUB_TAB[sub] ? sub : null;
}

/* ── Tab and sub-view switching ───────────────── */
window.deTab = function(tab) { deSwitch(_tabSub[tab] || tab); };

window.deSwitch = function(id) {
    const sub = resolve(id);
    if (!sub) return;
    const tab = SUB_TAB[sub];
    const panel = $('de-tab-' + tab);
    if (!panel || !panel.querySelector('[data-sub="' + sub + '"]')) return;
    _activeSub = sub;
    _tabSub[tab] = sub;
    document.querySelectorAll('.dx-tab').forEach(t => {
        const on = t.dataset.tab === tab;
        t.classList.toggle('active', on);
        t.setAttribute('aria-selected', on ? 'true' : 'false');
    });
    document.querySelectorAll('.de-panel').forEach(p => p.classList.toggle('active', p.dataset.tabPanel === tab));
    panel.querySelectorAll('.dx-subtab[data-subtab]').forEach(b => b.classList.toggle('active', b.dataset.subtab === sub));
    panel.querySelectorAll('.dx-subpanel').forEach(p => { p.hidden = p.dataset.sub !== sub; });
    panel.querySelectorAll('[data-sub-note]').forEach(n => { n.hidden = n.dataset.subNote !== sub; });
    if (location.hash !== '#' + sub) history.replaceState(null, '', location.pathname + location.search + '#' + sub);
    if (tab === 'work' && !_loaded.contentPack) loadContentPack();
    return _loaded[sub] ? Promise.resolve(true) : loadSub(sub);
};

window.deRefresh = function() {
    _loaded = {};
    deCloseDrawer();
    return loadSub(_activeSub);
};

/* The fragment for each sub-view, and the query it carries. */
function subUrl(sub) {
    const system = _selectedSystemId ? 'system_id=' + encodeURIComponent(_selectedSystemId) : '';
    switch (sub) {
        case 'overview': return '/ui/detection-engineering/overview';
        case 'attack': return '/ui/detection-engineering/coverage' + (system ? '?' + system : '');
        case 'd3fend': return '/ui/detection-engineering/d3fend';
        case 'systems': return _openSystemId
            ? '/ui/detection-engineering/systems/' + encodeURIComponent(_openSystemId)
            : '/ui/detection-engineering/systems' + (system ? '?' + system : '');
        case 'rules': return '/ui/detection-engineering/rules?' + new URLSearchParams(_rulesQuery).toString();
        case 'health': return '/ui/detection-engineering/health';
        case 'killchains': return '/ui/detection-engineering/killchains';
        case 'progression': return '/ui/detection-engineering/progression?hours=' + encodeURIComponent(_progHours);
        case 'readiness': return '/ui/detection-engineering/readiness';
        case 'emulation': return '/ui/detection-engineering/emulation';
        case 'vulns': return '/ui/detection-engineering/vulns';
        case 'requests': return '/ui/detection-engineering/work/requests';
        case 'proposals': return '/ui/detection-engineering/work/proposals' + location.search;
        case 'quirks': return '/ui/detection-engineering/work/quirks';
        case 'scorecard': return '/ui/detection-engineering/bob/scorecard';
        case 'disagreements': return '/ui/detection-engineering/bob/disagreements';
        case 'abuse': return '/ui/detection-engineering/bob/abuse';
    }
    return null;
}

async function loadSub(sub) {
    if (sub === 'readiness') return loadReadiness();
    const url = subUrl(sub);
    if (!url) return;
    _loaded[sub] = await deLoadFragment(url, 'de-panel-' + sub, 'Loading...');
}
window.deReloadSub = function(sub) { _loaded[sub] = false; if (_activeSub === sub) loadSub(sub); };

/* Any control that names a tab, and optionally a sub-view, moves there. */
window.deGo = function(sub) { deSwitch(sub); };

/* ── Rules: filters, paging and the drawer ────── */
window.deRulesFilter = function() {
    const form = $('de-rules-filters');
    if (!form) return;
    _rulesQuery = {
        q: form.querySelector('[name="q"]').value,
        kind: form.querySelector('[name="kind"]').value,
        severity: form.querySelector('[name="severity"]').value,
        state: form.querySelector('[name="state"]').value,
        problems: form.querySelector('[name="problems"]').checked ? '1' : '',
        offset: 0,
    };
    deLoadFragment(subUrl('rules') + '&body=1', 'de-rules-body', 'Loading rules...');
};
window.deRulesPage = function(offset) {
    _rulesQuery.offset = Math.max(0, Number(offset) || 0);
    deLoadFragment(subUrl('rules') + '&body=1', 'de-rules-body', 'Loading rules...');
};
window.deOpenRule = async function(key) {
    const host = $('de-drawer-host');
    document.querySelectorAll('tr[data-rule-key]').forEach(r => r.classList.toggle('dx-sel', r.dataset.ruleKey === key));
    await deLoadFragment('/ui/detection-engineering/rules/drawer?key=' + encodeURIComponent(key), host, 'Loading rule...', {quiet:true});
};
function deCloseDrawer() {
    const host = $('de-drawer-host');
    if (host) host.replaceChildren();
    document.querySelectorAll('tr.dx-sel').forEach(r => r.classList.remove('dx-sel'));
}
window.deCloseDrawer = deCloseDrawer;
document.addEventListener('keydown', e => { if (e.key === 'Escape') deCloseDrawer(); });

window.deAttackGuidance = function(rule) {
    deLoadFragment('/ui/detection-engineering/health/attack?rule=' + encodeURIComponent(rule), 'de-attack-guidance', 'Reading MITRE guidance...');
};
window.deHideAttack = function() {
    const host = $('de-attack-guidance');
    if (host) host.replaceChildren();
};
/* Drafts a proposal from the rule's FP closures and saves it as a draft,
   the way the Work tab's requests do. */
window.deDraftForRule = async function(rule) {
    const say = (m, k) => (typeof window.showToast === 'function' ? window.showToast(m, k) : (k === 'error' && alert(m)));
    const post = async (path, body) => {
        const r = await fetch('/api/de' + path, {method:'POST', credentials:'include',
            headers:{'Content-Type':'application/json'}, body: JSON.stringify(body)});
        const j = await r.json().catch(() => ({}));
        if (!r.ok) throw new Error(j.detail || ('HTTP ' + r.status));
        return j;
    };
    try {
        const proposal = await post('/proposals', await post('/proposals/draft', {rule_name: rule, days: 90}));
        say('Draft proposal #' + proposal.id + ' created for ' + rule + '. It is under Work > Proposals.', 'success');
        window.deReloadSub('proposals');
    } catch (error) {
        say('Draft failed: ' + error.message, 'error');
    }
};

/* ── Systems: list and detail ─────────────────── */
window.deOpenSystem = function(id) {
    _openSystemId = id || '';
    _loaded.systems = false;
    if (_activeSub === 'systems') loadSub('systems');
    else deSwitch('systems');
};
window.deCloseSystem = function() { deOpenSystem(''); };

/* The system's Coverage and Readiness buttons set the header's System
   filter, which both of those tabs follow. */
window.deCoverageForSystem = function(id) { deChangeSystem(id); deSwitch('attack'); };
window.deReadinessForSystem = function(id) { deChangeSystem(id); deSwitch('readiness'); };

/* ── Log source register (was Log Source Health) ─ */
const LS_API = '/api/log-sources';
function lsReload() { _loaded.systems = false; if (_activeSub === 'systems') loadSub('systems'); }
async function lsJson(url, options) {
    const r = await fetch(url, Object.assign({credentials:'include'}, options || {}));
    const j = await r.json().catch(() => ({}));
    if (!r.ok) throw new Error(j.detail || ('HTTP ' + r.status));
    return j;
}
window.lsSeedDefaults = async function() {
    try { await lsJson(LS_API + '/seed-defaults', {method:'POST'}); lsReload(); }
    catch (e) { alert('Seed failed: ' + e.message); }
};
async function lsOpenForm(source) {
    const dialog = $('ls-dialog');
    if (!dialog) return;
    const form = $('ls-form');
    const field = name => form.querySelector('[name="' + name + '"]');
    const category = field('category');
    if (!category.options.length) {
        try {
            for (const c of (await lsJson(LS_API + '/categories')).categories || []) {
                const o = document.createElement('option');
                o.value = c.id; o.textContent = c.label;
                category.appendChild(o);
            }
        } catch (e) { /* the select stays empty and the browser refuses the submit */ }
    }
    const q = (source && source.query) || {};
    $('ls-modal-title').textContent = source ? 'Edit log source' : 'New log source';
    field('id').value = source ? source.id : '';
    field('name').value = source ? source.name : '';
    if (source) category.value = source.category;
    field('match_field').value = q.match_field || '';
    field('match_value').value = q.match_value || '';
    field('index_pattern').value = source ? (source.index_pattern || '') : '';
    field('interval').value = source ? source.expected_interval_minutes : 30;
    field('criticality').value = source ? source.criticality : 'medium';
    field('owner').value = source ? (source.owner || '') : '';
    field('tags').value = source ? (source.tags || []).join(', ') : '';
    field('description').value = source ? (source.description || '') : '';
    dialog.showModal();
}
window.lsNewSource = function() { lsOpenForm(null); };
window.lsCloseForm = function() { const d = $('ls-dialog'); if (d && d.open) d.close(); };
window.lsEdit = async function(id) {
    try { lsOpenForm(await lsJson(LS_API + '/' + id)); } catch (e) { alert('Could not open the source: ' + e.message); }
};
window.lsDelete = async function(id) {
    if (!confirm('Delete this log source?')) return;
    try { await lsJson(LS_API + '/' + id, {method:'DELETE'}); lsReload(); } catch (e) { alert('Delete failed: ' + e.message); }
};
window.lsSubmit = async function(event) {
    if (event) event.preventDefault();
    const form = $('ls-form');
    const v = name => form.querySelector('[name="' + name + '"]').value.trim();
    const id = v('id');
    const body = {
        name: v('name'), category: v('category'),
        query: {match_field: v('match_field'), match_value: v('match_value')},
        index_pattern: v('index_pattern') || null,
        expected_interval_minutes: parseInt(v('interval'), 10) || 30,
        criticality: v('criticality'), owner: v('owner') || null, description: v('description') || null,
        tags: v('tags').split(',').map(t => t.trim()).filter(Boolean),
    };
    try {
        await lsJson(id ? LS_API + '/' + id : LS_API, {method: id ? 'PATCH' : 'POST',
            headers: {'Content-Type': 'application/json'}, body: JSON.stringify(body)});
        lsCloseForm();
        lsReload();
    } catch (e) {
        alert('Save failed: ' + e.message);
    }
    return false;
};

/* ── Coverage map ─────────────────────────────── */
window.deCoverageTactic = function(name) {
    const root = $('de-panel-attack');
    root.querySelectorAll('.dx-mcol').forEach(c => {
        const on = c.dataset.tactic === name;
        c.classList.toggle('on', on);
        c.setAttribute('aria-pressed', on ? 'true' : 'false');
    });
    root.querySelectorAll('[data-tactic-panel]').forEach(p => { p.hidden = p.dataset.tacticPanel !== name; });
};
/* Dims techniques outside the chosen system's platforms. */
window.dePlatformScope = function(target) {
    const button = target.closest('button');
    const on = !button.classList.contains('on');
    button.classList.toggle('on', on);
    button.setAttribute('aria-pressed', on ? 'true' : 'false');
    const matrix = $('de-attack-matrix');
    if (matrix) matrix.classList.toggle('scoped', on);
};

/* ── System scope ─────────────────────────────── */
async function deLoadSystems() {
    const selector = $('de-system-select');
    const ok = await deLoadFragment('/ui/detection-engineering/system-options', selector, 'Loading systems...', {failure:'Systems unavailable'});
    $('de-system-wrap').hidden = !ok || selector.options.length < 2;
    selector.value = _selectedSystemId;
}
window.deChangeSystem = function(id) {
    _selectedSystemId = id || '';
    const header = $('de-system-select');
    if (header && header.value !== _selectedSystemId) header.value = _selectedSystemId;
    const local = $('de-readiness-system');
    if (local && local.value !== _selectedSystemId) local.value = _selectedSystemId;
    document.querySelectorAll('#de-readiness-body [data-click-action="deGenerateReport"]').forEach(button => {
        button.textContent = _selectedSystemId ? 'Assess (System)' : 'Assess (Global)';
    });
    _loaded.attack = false;
    _loaded.systems = false;
    if (_activeSub === 'attack' || _activeSub === 'systems') loadSub(_activeSub);
};

/* ── Use cases ────────────────────────────────── */
window.deProgSetHours = function(h) {
    _progHours = h;
    _loaded.progression = false;
    loadSub('progression');
};

/* ── Readiness ────────────────────────────────── */
window.__setSelectedSystemId = function(event) { deChangeSystem(event.target.value); };
async function loadReadiness() {
    if (!await deLoadFragment('/ui/detection-engineering/readiness', 'de-panel-readiness', 'Loading systems...')) return;
    $('de-readiness-search').value = _readinessSearch;
    $('de-readiness-system').value = _selectedSystemId;
    await fetchReadiness();
}
window.deReadinessSearch = function() {
    _readinessSearch = $('de-readiness-search').value;
    deChangeSystem($('de-readiness-system').value);
    fetchReadiness();
};
async function fetchReadiness() {
    _loaded.readiness = await deLoadFragment('/ui/detection-engineering/readiness/actors?search=' + encodeURIComponent(_readinessSearch),
        'de-readiness-body', 'Querying OpenCTI + TIDE...');
    if (_loaded.readiness) {
        $('de-readiness-body').querySelectorAll('[data-click-action="deGenerateReport"]').forEach(button => {
            button.textContent = _selectedSystemId ? 'Assess (System)' : 'Assess (Global)';
        });
    }
}
window.toggleActorDetail = function(el) { el.closest('.de-actor').classList.toggle('open'); };
window.deGenerateReport = async function(actorId, actorType, event) {
    const btn = event ? event.target.closest('button') : document.activeElement;
    btn.disabled = true;
    btn.textContent = 'Assessing...';
    try {
        await deLoadFragment('/ui/detection-engineering/readiness/system', 'de-sysreadiness-' + actorId, 'Assessing...',
            {method: 'POST', values: {actor_id: actorId, actor_type: actorType, system_id: _selectedSystemId}});
    } finally {
        btn.disabled = false;
        btn.textContent = _selectedSystemId ? 'Assess (System)' : 'Assess (Global)';
    }
};
window.deDownloadPdf = async function(actorId, actorType, event) {
    const btn = event ? event.target.closest('button') : document.activeElement;
    btn.disabled = true;
    btn.textContent = 'Generating report...';
    try {
        const payload = {actor_id: actorId, actor_type: actorType, generate_ai: true};
        if (_selectedSystemId) payload.system_id = _selectedSystemId;
        const resp = await fetch(API + '/tide/de/readiness-pdf', {
            method: 'POST', headers: {'Content-Type': 'application/json'}, credentials: 'include', body: JSON.stringify(payload),
        });
        if (!resp.ok) {
            const err = await resp.json().catch(() => ({detail:'Report generation failed'}));
            alert(err.detail || 'Failed');
            return;
        }
        const contentType = resp.headers.get('Content-Type') || '';
        const url = URL.createObjectURL(await resp.blob());
        if (contentType.includes('application/pdf')) {
            const a = document.createElement('a');
            a.href = url;
            a.download = resp.headers.get('Content-Disposition')?.split('filename=')[1]?.replace(/"/g, '') || 'readiness_report.pdf';
            document.body.appendChild(a);
            a.click();
            a.remove();
        } else {
            window.open(url, '_blank');
        }
    } catch (e) {
        alert('Report failed: ' + e.message);
    } finally {
        btn.disabled = false;
        btn.textContent = 'Download PDF';
    }
};

/* ── Emulation plans ──────────────────────────── */
let _emCurrentPlan = null;
function emReload() { _loaded.emulation = false; loadSub('emulation'); }
window.emCreatePrompt = async function() {
    const name = prompt('Plan name:');
    if (!name) return;
    const actor = prompt('Threat actor (optional):') || null;
    const r = await fetch('/api/emulation/plans', {
        method: 'POST', headers: {'Content-Type': 'application/json'}, credentials: 'include',
        body: JSON.stringify({name, actor_name: actor}),
    });
    if (r.ok) emReload();
};
window.emDeletePlan = async function(id) {
    if (!confirm('Delete this plan and all its steps?')) return;
    await fetch(`/api/emulation/plans/${id}`, {method: 'DELETE', credentials: 'include'});
    emReload();
};
window.emOpenPlan = async function(id) {
    _emCurrentPlan = id;
    return deLoadFragment(`/ui/detection-engineering/emulation/${encodeURIComponent(id)}`, 'de-emulation-detail', 'Loading emulation plan');
};
window.emAddStep = async function(planId) {
    const title = $('em-newstep-title').value.trim();
    if (!title) return;
    const tids = ($('em-newstep-tids').value || '').split(',').map(s => s.trim().toUpperCase()).filter(Boolean);
    await fetch(`/api/emulation/plans/${planId}/steps`, {
        method: 'POST', headers: {'Content-Type': 'application/json'}, credentials: 'include',
        body: JSON.stringify({title, mitre_techniques: tids}),
    });
    emOpenPlan(planId);
};
window.emExecuteStep = async function(id) {
    await fetch(`/api/emulation/steps/${id}/execute`, {method: 'POST', credentials: 'include'});
    if (_emCurrentPlan) emOpenPlan(_emCurrentPlan);
};
window.emVerifyStep = async function(id) {
    const r = await fetch(`/api/emulation/steps/${id}/verify?lookback_hours=4`, {method: 'POST', credentials: 'include'});
    const j = await r.json();
    if (j.error) alert('Verify warning: ' + j.error);
    if (_emCurrentPlan) emOpenPlan(_emCurrentPlan);
};
window.emDeleteStep = async function(id) {
    if (!confirm('Delete step?')) return;
    await fetch(`/api/emulation/steps/${id}`, {method: 'DELETE', credentials: 'include'});
    if (_emCurrentPlan) emOpenPlan(_emCurrentPlan);
};

/* ── Vulnerability coverage ───────────────────── */
function vlnReload() { _loaded.vulns = false; loadSub('vulns'); }
window.vlnCreatePrompt = async function() {
    const title = prompt('Vulnerability title:');
    if (!title) return;
    const cve = prompt('CVE ID (optional, e.g. CVE-2025-12345):') || null;
    const sev = prompt('Severity (critical / high / medium / low / info):', 'medium') || 'medium';
    const tids = prompt('ATT&CK techniques used to exploit (comma-separated, e.g. T1190, T1059):') || '';
    const r = await fetch('/api/vulnerabilities', {
        method: 'POST', headers: {'Content-Type': 'application/json'}, credentials: 'include',
        body: JSON.stringify({title, cve_id: cve, severity: sev,
            mitre_techniques: tids.split(',').map(s => s.trim().toUpperCase()).filter(Boolean)}),
    });
    if (r.ok) vlnReload();
};
window.vlnDelete = async function(id) {
    if (!confirm('Delete this vulnerability?')) return;
    await fetch(`/api/vulnerabilities/${id}`, {method: 'DELETE', credentials: 'include'});
    vlnReload();
};

/* ── Work: content pack menu ──────────────────── */
async function loadContentPack() {
    _loaded.contentPack = await deLoadFragment('/ui/detection-engineering/work/content-pack', 'de-content-pack', '', {quiet:true});
}
window.deToggleMenu = function(id) {
    const menu = $(id);
    if (menu) menu.hidden = !menu.hidden;
};
document.addEventListener('click', e => {
    if (e.target.closest('[data-click-action="deToggleMenu"], .dx-menu-list')) return;
    document.querySelectorAll('.dx-menu-list').forEach(m => { m.hidden = true; });
});

/* ── TIDE sync, destination and access ────────── */
window.deSyncTide = async function() {
    deSetBadge('Syncing...');
    try {
        const response = await fetch(API + '/tide/de/sync-now', {method:'POST', credentials:'include'});
        if (!response.ok) throw new Error('Sync failed');
        const payload = await response.json();
        if (!payload || payload.error) {
            deSetBadge(payload && typeof payload.error === 'string' ? 'TIDE (' + payload.error + ')' : 'TIDE (sync failed)');
            return;
        }
        deSetBadge('TIDE · synced ' + (payload.synced ?? 'Unknown') + '/' + (payload.total ?? 'Unknown') + ' just now', true);
        deRefresh();
    } catch (error) {
        deSetBadge('TIDE (sync failed)');
    }
};

function deAge(seconds) {
    if (seconds < 90) return 'just now';
    if (seconds < 5400) return Math.round(seconds / 60) + ' min ago';
    if (seconds < 129600) return Math.round(seconds / 3600) + ' h ago';
    return Math.round(seconds / 86400) + ' d ago';
}

async function deCheckSyncStatus() {
    try {
        const payload = await apiFetch('/tide/de/sync-status');
        if (!payload || typeof payload !== 'object' || !payload.datasets || typeof payload.datasets !== 'object') throw new Error('Invalid sync status');
        const healthy = Object.values(payload.datasets).filter(d => d && !d.error && typeof d.age_seconds === 'number');
        const total = payload.total_datasets;
        if (!healthy.length) { deSetBadge('TIDE · not synced yet'); return; }
        /* The oldest healthy dataset, so the pill never claims fresher data than it has. */
        const age = deAge(Math.max(...healthy.map(d => d.age_seconds)));
        const complete = typeof total === 'number' && healthy.length >= total;
        deSetBadge('TIDE · ' + (complete ? '' : healthy.length + '/' + (total ?? '?') + ' datasets · ') + 'synced ' + age, complete);
    } catch (error) {
        deSetBadge('TIDE · status unavailable');
    }
}

async function deLoadDestinations() {
    const selector = $('de-destination-select');
    selector.disabled = true;
    await deLoadFragment('/ui/detection-engineering/destinations', selector, 'Loading destinations...');
    selector.disabled = !selector.options.length || selector.options[0].disabled;
}

/* An empty key is "All destinations", a real choice rather than no choice. */
window.deChangeDestination = async function(key) {
    const selector = $('de-destination-select');
    selector.disabled = true;
    try {
        const response = await fetch(API + '/tide/de/destination', {
            method:'POST', credentials:'include', headers:{'Content-Type':'application/json'},
            body:JSON.stringify({key: key || ''}),
        });
        const payload = await response.json();
        if (!response.ok || !payload || payload.ok !== true) throw new Error('Destination switch failed');
        await deRefresh();
    } catch (error) {
        deSetBadge('TIDE (destination switch failed)');
    } finally {
        await deLoadDestinations();
    }
};

/* TIDE refusing ION's key or tenant leaves every panel empty; say why once,
   at the top, instead of letting the page read as a tenant with no rules. */
async function deCheckTideAccess() {
    const banner = $('de-tide-failure');
    try {
        const status = await apiFetch('/tide/status');
        const failure = status && status.ok === false ? status.failure : null;
        if (!failure || typeof failure.message !== 'string') { banner.hidden = true; return; }
        banner.querySelector('[data-failure-message]').textContent = failure.message;
        banner.querySelector('[data-failure-detail]').textContent = failure.detail ? 'TIDE said: ' + failure.detail : '';
        banner.hidden = false;
    } catch (error) {
        banner.hidden = true;
    }
}

function wantedFromHash() {
    return resolve(decodeURIComponent((location.hash || '').slice(1)));
}

/* The first panel, then the header's TIDE reads, one after another: ION
   sheds TIDE queries past three in flight, and these requests arriving
   together tripped it on an ordinary page load. */
document.addEventListener('DOMContentLoaded', async () => {
    deCheckSyncStatus();
    await deSwitch(wantedFromHash() || 'overview');
    await deLoadDestinations();
    await deLoadSystems();
    await deCheckTideAccess();
});
/* A link to #health or #quirks, or the back button, lands on that sub-view without a reload. */
window.addEventListener('hashchange', () => {
    const wanted = wantedFromHash();
    if (wanted && wanted !== _activeSub) deSwitch(wanted);
});
})();
